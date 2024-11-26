use core::{ptr::addr_of_mut, time::Duration};
use std::cell::UnsafeCell;
use std::fmt::format;
use std::{path::PathBuf, process};
use libafl_bolts::math;
use log::*;
use std::ptr;
use libafl::{
    corpus::Corpus, executors::ExitKind, feedback_or, feedback_or_fast, feedbacks::{AflMapFeedback, CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback}, fuzzer::{Fuzzer, StdFuzzer}, inputs::{BytesInput, Input}, mutators::scheduled::{havoc_mutations, StdScheduledMutator}, observers::{stream::StreamObserver, CanTrack, HitcountsMapObserver, TimeObserver, VariableMapObserver}, prelude::{powersched::PowerSchedule, CachedOnDiskCorpus, PowerQueueScheduler, SimpleEventManager, SimpleMonitor}, stages::StdMutationalStage, state::{HasCorpus, StdState}
};
use libafl_bolts::tuples::MatchNameRef;
use libafl::feedbacks::stream::StreamFeedback;
use libafl::inputs::multi::MultipartInput;
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
static mut SMM_INIT_FUZZ_INDEX : u64 = 1;

fn gen_init_random_seed(dir : &PathBuf) {
    let mut initial_input = MultipartInput::<BytesInput>::new();
    initial_input.add_part(0 as u128, BytesInput::new(DEFAULT_STREAM_DATA.to_vec()),0x10);
    let mut init_seed_path = PathBuf::new(); 
    init_seed_path.push(dir.clone());
    init_seed_path.push(PathBuf::from("init.bin"));
    initial_input.to_file(init_seed_path).unwrap();
}


pub fn init_phase_fuzz(emulator: &mut Emulator<NopCommandManager, NopEmulatorExitHandler, (EdgeCoverageModule, (CmpLogModule, ())), StdState<MultipartInput<BytesInput>, CachedOnDiskCorpus<MultipartInput<BytesInput>>, libafl_bolts::prelude::RomuDuoJrRand, CachedOnDiskCorpus<MultipartInput<BytesInput>>>>, snapshot : &FuzzerSnapshot) -> SnapshotKind 
{
    let qemu = emulator.qemu();
    let cpu = qemu.first_cpu().unwrap();
    snapshot.restore_fuzz_snapshot(qemu, true);
    unsafe {
        SMM_INIT_FUZZ_EXIT_SNAPSHOT = ptr::null_mut();

    }

    let corpus_dir = PathBuf::from(INIT_PHASE_CORPUS_DIR).join(PathBuf::from(format!("init_phase_corpus_{}/", unsafe {SMM_INIT_FUZZ_INDEX})));
    let objective_dir = PathBuf::from(INIT_PHASE_SOLUTION_DIR).join(PathBuf::from(format!("init_phase_crash_{}/", unsafe {SMM_INIT_FUZZ_INDEX})));
    let seed_dirs = [PathBuf::from(INIT_PHASE_SEED_DIR).join(PathBuf::from(format!("init_phase_seed_{}/", unsafe {SMM_INIT_FUZZ_INDEX})))];
    fs::create_dir_all(corpus_dir.clone()).unwrap();
    fs::create_dir_all(objective_dir.clone()).unwrap();
    fs::create_dir_all(seed_dirs[0].clone()).unwrap();
    gen_init_random_seed(&seed_dirs[0]);
    unsafe {
        SMM_INIT_FUZZ_INDEX += 1;
    }
    

    let mut harness = |input: & MultipartInput<BytesInput>, state: &mut QemuExecutorState<_, _, _, _>| {
        
        debug!("new run");
        let mut inputs = StreamInputs::from_multiinput(input);
        unsafe {  
            GLOB_INPUT = (&mut inputs) as *mut StreamInputs;
        }
        let in_simulator = state.emulator_mut();
        let in_qemu: Qemu = in_simulator.qemu();
        let in_cpu = in_qemu.first_cpu().unwrap();
        let (qemu_exit_reason, pc, cmd, sync_exit_reason, arg1, arg2) = qemu_run_once(in_qemu, snapshot, 30000000,false, true);
        let exit_code;
        debug!("new run exit {:?}",qemu_exit_reason);
        if let Ok(qemu_exit_reason) = qemu_exit_reason
        {
            if let QemuExitReason::SyncExit = qemu_exit_reason  {
                debug!("qemu_run_to_end sync exit {:#x} {:#x} {:#x}",cmd,sync_exit_reason,pc);
                if cmd == LIBAFL_QEMU_COMMAND_END {
                    match sync_exit_reason {
                        LIBAFL_QEMU_END_CRASH => {
                            exit_code = ExitKind::Ok; // init phase does not have crash we assume
                        },
                        LIBAFL_QEMU_END_SMM_INIT_END => {
                            unsafe {
                                if SMM_INIT_FUZZ_EXIT_SNAPSHOT.is_null() {
                                    let box_snap = Box::new(FuzzerSnapshot::from_qemu(in_qemu));
                                    // info!("found the way to pass init function");
                                    SMM_INIT_FUZZ_EXIT_SNAPSHOT = Box::into_raw(box_snap);
                                }
                            }
                            exit_code = ExitKind::Ok;
                        },
                        LIBAFL_QEMU_END_SMM_INIT_UNSUPPORT => {
                            exit_code = ExitKind::Ok;
                        },
                        _ => {
                            exit_elegantly();
                            exit_code = ExitKind::Ok;
                        },
                    }
                }
                else {
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
                exit_elegantly();
                exit_code = ExitKind::Ok;
            }
            else if let QemuExitReason::Breakpoint(_) = qemu_exit_reason {
                exit_elegantly();
                exit_code = ExitKind::Ok;
            }
            else {
                exit_elegantly();
                exit_code = ExitKind::Ok;
            }
        }
        else    {
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

    let mutator = StdScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));
    let mut shadow_executor = ShadowExecutor::new(executor, tuple_list!(cmplog_observer));
    let i2s = StdMutationalStage::new(StdScheduledMutator::new(tuple_list!(
        I2SRandReplace::new()
    )));

    let mut stages = tuple_list!(ShadowTracingStage::new(&mut shadow_executor),i2s, StdMutationalStage::new(mutator));

    
    loop {
        if unsafe { !SMM_INIT_FUZZ_EXIT_SNAPSHOT.is_null() } {
            let exit_snapshot = unsafe { Box::from_raw(SMM_INIT_FUZZ_EXIT_SNAPSHOT) };
            let (qemu_exit_reason, pc, cmd, sync_exit_reason, arg1, arg2) = qemu_run_once(qemu, &exit_snapshot,800000000, true, false);
            if let Ok(ref qemu_exit_reason) = qemu_exit_reason {
                if let QemuExitReason::SyncExit = qemu_exit_reason {
                    if cmd == LIBAFL_QEMU_COMMAND_END {
                        if sync_exit_reason == LIBAFL_QEMU_END_SMM_INIT_START {
                            set_current_module(arg1, arg2);
                            return SnapshotKind::StartOfSmmInitSnap(FuzzerSnapshot::from_qemu(qemu));
                        }
                        else if sync_exit_reason == LIBAFL_QEMU_END_SMM_MODULE_START {
                            return SnapshotKind::StartOfSmmModuleSnap(FuzzerSnapshot::from_qemu(qemu));
                        }
                    }
                } else if let QemuExitReason::End(_) = qemu_exit_reason {
                    exit_elegantly();
                }
            }

            unsafe {
                exit_snapshot.delete(qemu);
                SMM_INIT_FUZZ_EXIT_SNAPSHOT = ptr::null_mut();
            }
            snapshot.restore_fuzz_snapshot(qemu, true);
            warn!("smm init found {:?} {pc:#x} {cmd:#x} {sync_exit_reason:#x}",qemu_exit_reason);
            
        }
        fuzzer
            .fuzz_one(&mut stages, &mut shadow_executor, &mut state, &mut mgr)
            .unwrap();
    }
    
    exit_elegantly();
    SnapshotKind::None

}