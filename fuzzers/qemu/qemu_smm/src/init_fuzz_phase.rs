use core::{ptr::addr_of_mut, time::Duration};
use std::cell::UnsafeCell;
use std::fmt::format;
use std::{path::PathBuf, process};
use libafl::state::{HasLastFoundTime, HasStartTime};
use libafl_bolts::math;
use log::*;
use std::ptr;
use rand::Rng;
use libafl::{
    corpus::Corpus,Error, executors::ExitKind, feedback_or, feedback_or_fast, feedbacks::{AflMapFeedback, CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback}, fuzzer::{Fuzzer, StdFuzzer}, inputs::{BytesInput, Input}, mutators::scheduled::{havoc_mutations, StdScheduledMutator}, observers::{stream::StreamObserver, CanTrack, HitcountsMapObserver, TimeObserver, VariableMapObserver}, prelude::{powersched::PowerSchedule, CachedOnDiskCorpus, PowerQueueScheduler, SimpleEventManager, SimpleMonitor}, stages::StdMutationalStage, state::{HasCorpus, StdState}
};
use libafl_bolts::tuples::MatchNameRef;
use libafl::feedbacks::stream::StreamFeedback;
use libafl::inputs::multi::MultipartInput;
use libafl::prelude::IfStage;
use std::sync::{Arc, Mutex};
use std::{error, fs};
use libafl_bolts::{
    current_nanos,
    ownedref::OwnedMutSlice,
    rands::StdRand,
    shmem::ShMemProvider,
    tuples::tuple_list,
};
use once_cell::sync::Lazy;
use libafl_qemu::{
    command::NopCommandManager, executor::{stateful::StatefulQemuExecutor, QemuExecutorState}, modules::edges::{
        edges_map_mut_ptr, EdgeCoverageModule, EdgeCoverageClassicModule, EDGES_MAP_SIZE_IN_USE, MAX_EDGES_FOUND,
    }, Emulator, NopEmulatorExitHandler, PostDeviceregReadHookId, PreDeviceregWriteHookId, Qemu, QemuExitReason, Regs
};
use libafl_qemu_sys::GuestAddr;
use libafl_qemu::{emu, Hook};
use libafl_qemu::modules::edges::gen_hashed_block_ids;
use libafl_qemu::GuestReg;
use libafl_qemu::qemu::BlockHookId;
use libafl_qemu::CPU;
use libafl_qemu::DeviceSnapshotFilter;
use libafl_qemu::FastSnapshotPtr;
use libafl_qemu::command::CommandManager;
use libafl_qemu::EmulatorExitHandler;
use libafl_qemu::modules::EmulatorModuleTuple;
use libafl::prelude::State;
use libafl::prelude::HasExecutions;
use libafl_qemu::modules::CmpLogModule;
use libafl_qemu::QemuExecutor;
use libafl_qemu::modules::cmplog::CmpLogObserver;
use libafl::executors::ShadowExecutor;
use libafl::stages::ShadowTracingStage;
use libafl_bolts::tuples::Merge;
use libafl::prelude::tokens_mutations;
use libafl::mutators::I2SRandReplace;
use std::env;
use crate::stream_input::*;
use crate::qemu_args::*;
use crate::common_hooks::*;
use crate::config::*;
use crate::exit_qemu::*;
use crate::fuzzer_snapshot::*;
use crate::qemu_control::*;
use crate::smm_fuzz_qemu_cmds::*;

static mut SMM_INIT_FUZZ_EXIT_SNAPSHOT : *mut FuzzerSnapshot = ptr::null_mut();

static mut CRASH_TIMES : u64 = 0;

fn gen_init_random_seed(dir : &PathBuf) {
    let mut initial_input = MultipartInput::<BytesInput>::new();
    initial_input.add_part(0 as u128, BytesInput::new(DEFAULT_STREAM_DATA.to_vec()),0x10);
    let mut init_seed_path = PathBuf::new(); 
    init_seed_path.push(dir.clone());
    init_seed_path.push(PathBuf::from("init.bin"));
    initial_input.to_file(init_seed_path).unwrap();
}


fn try_run_without_fuzz(qemu : Qemu) -> SnapshotKind {
    let (qemu_exit_reason, pc, cmd, sync_exit_reason, arg1, arg2) = qemu_run_once(qemu, &FuzzerSnapshot::new_empty(), 30000000,false, false);
    if cmd == LIBAFL_QEMU_COMMAND_END {
        if sync_exit_reason == LIBAFL_QEMU_END_SMM_INIT_END {
            let (qemu_exit_reason, pc, cmd, sync_exit_reason, arg1, arg2) = qemu_run_once(qemu, &FuzzerSnapshot::new_empty(), 800000000,false, false);
            if cmd == LIBAFL_QEMU_COMMAND_END {
                if sync_exit_reason == LIBAFL_QEMU_END_SMM_INIT_START {
                    set_current_module(arg1, arg2);
                    return SnapshotKind::StartOfSmmInitSnap(FuzzerSnapshot::from_qemu(qemu));
                }
                else if sync_exit_reason == LIBAFL_QEMU_END_SMM_MODULE_START {
                    return SnapshotKind::StartOfSmmModuleSnap(FuzzerSnapshot::from_qemu(qemu));
                }
            }
        }
    }
    return SnapshotKind::None;
}

pub fn init_phase_fuzz(module_index : usize, emulator: &mut Emulator<NopCommandManager, NopEmulatorExitHandler, (EdgeCoverageModule, (CmpLogModule, ())), StdState<MultipartInput<BytesInput>, CachedOnDiskCorpus<MultipartInput<BytesInput>>, libafl_bolts::prelude::RomuDuoJrRand, CachedOnDiskCorpus<MultipartInput<BytesInput>>>>) -> SnapshotKind 
{
    let qemu = emulator.qemu();
    let cpu = qemu.first_cpu().unwrap();
    let snapshot = FuzzerSnapshot::from_qemu(qemu);
    unsafe {
        SMM_INIT_FUZZ_EXIT_SNAPSHOT = ptr::null_mut();
        CRASH_TIMES = 0;
    }
    unskip();

    let corpus_dir = PathBuf::from(INIT_PHASE_CORPUS_DIR).join(PathBuf::from(format!("init_phase_corpus_{}/", module_index)));
    let objective_dir = PathBuf::from(INIT_PHASE_SOLUTION_DIR).join(PathBuf::from(format!("init_phase_crash_{}/", module_index)));
    let seed_dirs = [PathBuf::from(INIT_PHASE_SEED_DIR).join(PathBuf::from(format!("init_phase_seed_{}/", module_index)))];
    if fs::metadata(corpus_dir.clone()).is_ok() {
        fs::remove_dir_all(corpus_dir.clone()).unwrap();
    }
    if fs::metadata(objective_dir.clone()).is_ok() {
        fs::remove_dir_all(objective_dir.clone()).unwrap();
    }
    if fs::metadata(seed_dirs[0].clone()).is_ok() {
        fs::remove_dir_all(seed_dirs[0].clone()).unwrap();
    }
    
    fs::create_dir_all(corpus_dir.clone()).unwrap();
    fs::create_dir_all(objective_dir.clone()).unwrap();
    fs::create_dir_all(seed_dirs[0].clone()).unwrap();

    gen_init_random_seed(&seed_dirs[0]);
    
    let try_snapshot = try_run_without_fuzz(qemu);
    if let SnapshotKind::None = try_snapshot {
        snapshot.restore_fuzz_snapshot(qemu, true);
    } else {
        snapshot.delete(qemu);
        return try_snapshot;
    }

    let mut harness = |input: & MultipartInput<BytesInput>, state: &mut QemuExecutorState<_, _, _, _>| {
        
        debug!("new run");
        let mut inputs = StreamInputs::from_multiinput(input);
        unsafe {  
            GLOB_INPUT = (&mut inputs) as *mut StreamInputs;
        }
        let fuzz_input = unsafe {&mut (*GLOB_INPUT) };
        set_fuzz_mem_switch(fuzz_input);
        let in_simulator = state.emulator_mut();
        let in_qemu: Qemu = in_simulator.qemu();
        let in_cpu = in_qemu.first_cpu().unwrap();
        let (qemu_exit_reason, pc, cmd, sync_exit_reason, arg1, arg2) = qemu_run_once(in_qemu, &snapshot, 500000,false, true);
        let exit_code;
        debug!("new run exit {:?}",qemu_exit_reason);
        if let Ok(qemu_exit_reason) = qemu_exit_reason
        {
            if let QemuExitReason::SyncExit = qemu_exit_reason  {
                debug!("qemu_run_to_end sync exit {:#x} {:#x} {:#x}",cmd,sync_exit_reason,pc);
                if cmd == LIBAFL_QEMU_COMMAND_END {
                    match sync_exit_reason {
                        LIBAFL_QEMU_END_SMM_INIT_UNSUPPORT | LIBAFL_QEMU_END_SMM_ASSERT => {
                            unsafe {
                                CRASH_TIMES = 0;
                            }
                            exit_code = ExitKind::Ok; // init phase does not have crash we assume
                        },
                        LIBAFL_QEMU_END_SMM_INIT_END => {
                            unsafe {
                                if SMM_INIT_FUZZ_EXIT_SNAPSHOT.is_null() {
                                    let box_snap = Box::new(FuzzerSnapshot::from_qemu(in_qemu));
                                    SMM_INIT_FUZZ_EXIT_SNAPSHOT = Box::into_raw(box_snap);
                                }
                            }
                            exit_code = ExitKind::Ok;
                        },
                        LIBAFL_QEMU_END_CRASH => {
                            unsafe {
                                CRASH_TIMES += 1;
                                exit_code = ExitKind::Ok;
                            }
                        },
                        _ => {
                            error!("exit 1");
                            exit_elegantly();
                            exit_code = ExitKind::Ok;
                        },
                    }
                }
                else {
                    error!("exit 2");
                    exit_elegantly();
                    exit_code = ExitKind::Ok;
                }
            }
            else if let QemuExitReason::Timeout = qemu_exit_reason {
                exit_code = ExitKind::Ok;
            }
            else if let QemuExitReason::StreamNotFound = qemu_exit_reason {
                exit_code = ExitKind::Ok;
            }
            else if let QemuExitReason::StreamOutof = qemu_exit_reason {
                exit_code = ExitKind::Ok;
            }
            else if let QemuExitReason::End(_) = qemu_exit_reason {
                error!("Ctrl+C");
                exit_elegantly();
                exit_code = ExitKind::Ok;
            }
            else if let QemuExitReason::Breakpoint(_) = qemu_exit_reason {
                error!("exit 4");
                exit_elegantly();
                
                exit_code = ExitKind::Ok;
            }
            else {
                error!("exit 5");
                exit_elegantly();
                exit_code = ExitKind::Ok;
            }
        }
        else    {
            error!("exit 6");
            exit_elegantly();
            exit_code = ExitKind::Ok;
        }
        
            
        exit_code
    };
    let mut edges_observer = unsafe {
        HitcountsMapObserver::new(VariableMapObserver::from_mut_slice(
            "edges",
            OwnedMutSlice::from_raw_parts_mut(edges_map_mut_ptr(), EDGES_MAP_SIZE_IN_USE),
            addr_of_mut!(MAX_EDGES_FOUND),  
        ))
        .track_indices()
    };
    let time_observer = TimeObserver::new("time");
    let stream_observer = StreamObserver::new("stream", unsafe {Arc::clone(&STREAM_FEEDBACK)});
    let cmplog_observer = CmpLogObserver::new("cmplog", true);
    let mut feedback = feedback_or!(
        MaxMapFeedback::new(&edges_observer),
        TimeFeedback::new(&time_observer),
        StreamFeedback::new(&stream_observer),
    );
    
    // A feedback to choose if an input is a solution or not
    let mut objective = CrashFeedback::new();

    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        CachedOnDiskCorpus::<MultipartInput<BytesInput>>::new(corpus_dir.clone(),10 * 4096).unwrap(),
        CachedOnDiskCorpus::<MultipartInput<BytesInput>>::new(objective_dir,10 * 4096).unwrap(),
        &mut feedback,
        // Same for objective feedbacks
        &mut objective,
    ).unwrap();

    let mon = SimpleMonitor::new(|s| 
        info!("{s}")  
    );
    let mut mgr = SimpleEventManager::new(mon);
    let scheduler = PowerQueueScheduler::new(&mut state, &mut edges_observer, PowerSchedule::FAST);
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);


    let mut executor = StatefulQemuExecutor::new(
        emulator,
        &mut harness,
        tuple_list!(edges_observer, time_observer,stream_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        Duration::from_secs(100000),
    )
    .expect("Failed to create QemuExecutor");

    

    if state.must_load_initial_inputs() {
        state
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &seed_dirs)
            .unwrap_or_else(|_| {
                error!("Failed to load initial corpus at {:?}", &seed_dirs);
                exit_elegantly();
            });
            info!("We imported {} inputs from disk.", state.corpus().count());
    }


    let havoc_stage = StdMutationalStage::new(StdScheduledMutator::new(havoc_mutations().merge(tokens_mutations())));

    let cb = |_fuzzer: &mut _,
                  _executor: &mut _,
                  state: &mut _,
                  _event_manager: &mut _|
         -> Result<bool, Error> {
            let mut rng = rand::thread_rng();
            let random_number: i32 = rng.gen_range(1..=3);
            if random_number == 1 {
                Ok(true)
            } else {
                Ok(false)
            }
        };

    let op_havoc_stage = IfStage::new(cb, tuple_list!(havoc_stage));

    let mut shadow_executor = ShadowExecutor::new(executor, tuple_list!(cmplog_observer));
    let i2s = StdMutationalStage::new(StdScheduledMutator::new(tuple_list!(
        I2SRandReplace::new()
    )));

    let mut stages = tuple_list!(ShadowTracingStage::new(&mut shadow_executor),i2s, op_havoc_stage);

    
    loop {
        fuzzer
            .fuzz_one(&mut stages, &mut shadow_executor, &mut state, &mut mgr)
            .unwrap();
        if unsafe { !SMM_INIT_FUZZ_EXIT_SNAPSHOT.is_null() } {
            let exit_snapshot = unsafe { Box::from_raw(SMM_INIT_FUZZ_EXIT_SNAPSHOT) };
            let (qemu_exit_reason, pc, cmd, sync_exit_reason, arg1, arg2) = qemu_run_once(qemu, &exit_snapshot,800000000, true, false);
            if let Ok(ref qemu_exit_reason) = qemu_exit_reason {
                if let QemuExitReason::SyncExit = qemu_exit_reason {
                    if cmd == LIBAFL_QEMU_COMMAND_END {
                        if sync_exit_reason == LIBAFL_QEMU_END_SMM_INIT_START {
                            exit_snapshot.delete(qemu);
                            snapshot.delete(qemu);
                            set_current_module(arg1, arg2);
                            return SnapshotKind::StartOfSmmInitSnap(FuzzerSnapshot::from_qemu(qemu));
                        }
                        else if sync_exit_reason == LIBAFL_QEMU_END_SMM_MODULE_START {
                            exit_snapshot.delete(qemu);
                            snapshot.delete(qemu);
                            return SnapshotKind::StartOfSmmModuleSnap(FuzzerSnapshot::from_qemu(qemu));
                        }
                    }
                } else if let QemuExitReason::End(_) = qemu_exit_reason {
                    error!("fuzz one module over, run to next module error");
                    exit_elegantly();
                }
            }
            exit_snapshot.delete(qemu);
            unsafe {
                SMM_INIT_FUZZ_EXIT_SNAPSHOT = ptr::null_mut();
            }
            snapshot.restore_fuzz_snapshot(qemu, true);
            warn!("fuzz one module over, run to next module exit with {:?} {pc:#x} {cmd:#x} {sync_exit_reason:#x}",qemu_exit_reason);
        }
        // if unsafe {CRASH_TIMES} > 100 {
        //     if unsafe { !SMM_INIT_FUZZ_EXIT_SNAPSHOT.is_null() } {
        //         let exit_snapshot = unsafe { Box::from_raw(SMM_INIT_FUZZ_EXIT_SNAPSHOT) };
        //         exit_snapshot.delete(qemu);
        //     }
        //     snapshot.delete(qemu);
        //     return SnapshotKind::None;
        // }

        
        // if (*state.executions() > 20000) || (*state.executions() > 1000 && state.corpus().count() <= 1 ) {
        //     skip();
        // }
        if libafl_bolts::current_time().as_secs() - state.last_found_time().as_secs() > 60 * 1 {
            skip();
        }
    }
    unreachable!();

}