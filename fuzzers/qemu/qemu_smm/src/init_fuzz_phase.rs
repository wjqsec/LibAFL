use core::{ptr::addr_of_mut, time::Duration};
use std::cell::UnsafeCell;
use std::fmt::format;
use std::{path::PathBuf, process};
use libafl::state::{HasLastFoundTime, HasStartTime};
use libafl_bolts::math;
use log::*;
use uuid::uuid;
use std::ptr;
use rand::Rng;
use libafl::{
    corpus::Corpus,Error, executors::ExitKind, feedback_or, feedback_or_fast, feedbacks::{AflMapFeedback, CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback}, fuzzer::{Fuzzer, StdFuzzer}, inputs::{BytesInput, Input}, mutators::scheduled::{havoc_mutations, StdScheduledMutator}, observers::{stream::StreamObserver, CanTrack, HitcountsMapObserver, TimeObserver, VariableMapObserver}, prelude::{powersched::PowerSchedule, QueueScheduler, OnDiskCorpus, CachedOnDiskCorpus, InMemoryCorpus, PowerQueueScheduler, SimpleEventManager, SimpleMonitor}, stages::StdMutationalStage, state::{HasCorpus, StdState}
};
use libafl::events::ProgressReporter;
use libafl_bolts::tuples::MatchNameRef;
use libafl::feedbacks::stream::StreamFeedback;
use libafl::inputs::multi::MultipartInput;
use libafl::prelude::IfStage;
use std::sync::{Arc, Mutex};
use serde_json::Value;
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
use libafl::prelude::CorpusId;
use std::env;
use crate::stream_input::*;
use crate::qemu_args::*;
use crate::common_hooks::*;
use crate::exit_qemu::*;
use crate::fuzzer_snapshot::*;
use crate::smi_info::*;
use crate::qemu_control::*;
use crate::smm_fuzz_qemu_cmds::*;
use crate::coverage::*;


static mut SMM_INIT_FUZZ_EXIT_SNAPSHOT : *mut FuzzerSnapshot = ptr::null_mut();

static mut TIMEOUT_TIMES : u64 = 0;
static mut END_ERROR_TIMES : u64 = 0;
static mut CRASH_TIMES : u64 = 0;
static mut STREAM_OVER_TIMES : u64 = 0;
static mut ASSERT_TIMES : u64 = 0;
static mut NOTFOUND_TIMES : u64 = 0;

const INIT_FUZZ_TIMEOUT_BBL : u64 = 500000;
static mut INIT_FUZZ_TIMEOUT_TIME : u64 = 2 * 60;

pub fn set_init_fuzz_timeout_time(sec : u64) {
    unsafe {
        INIT_FUZZ_TIMEOUT_TIME = sec;
    }
}

fn gen_init_random_seed(dir : &PathBuf) {
    let mut initial_input = MultipartInput::<BytesInput>::new();
    initial_input.add_part(0 as u128, BytesInput::new(vec![]),0x10,0);
    let mut init_seed_path = PathBuf::new(); 
    init_seed_path.push(dir.clone());
    init_seed_path.push(PathBuf::from("init.bin"));
    initial_input.to_file(init_seed_path).unwrap();
}

fn try_run_without_fuzz(qemu : Qemu) -> SnapshotKind {
    let (qemu_exit_reason, pc, cmd, sync_exit_reason, arg1, arg2) = qemu_run_once(qemu, &FuzzerSnapshot::new_empty(), 50000000,false, false);
    if cmd == LIBAFL_QEMU_COMMAND_END && sync_exit_reason == LIBAFL_QEMU_END_SMM_INIT_END {
        let (qemu_exit_reason, pc, cmd, sync_exit_reason, arg1, arg2) = qemu_run_once(qemu, &FuzzerSnapshot::new_empty(), 500000000,false, false);
        if cmd == LIBAFL_QEMU_COMMAND_END {
            if sync_exit_reason == LIBAFL_QEMU_END_SMM_INIT_PREPARE {
                return SnapshotKind::StartOfSmmInitSnap(FuzzerSnapshot::new_empty());
            }
            else if sync_exit_reason == LIBAFL_QEMU_END_SMM_MODULE_START {
                return SnapshotKind::StartOfSmmModuleSnap(FuzzerSnapshot::new_empty());
            }
        }
        error!("run to next module or smm fuzz error {} {}",cmd, sync_exit_reason);
        exit_elegantly(ExitProcessType::Error);
    } 
    return SnapshotKind::None;
}

pub fn init_phase_fuzz(seed_dirs : PathBuf, corpus_dir : PathBuf, objective_dir : PathBuf, emulator: &mut Emulator<NopCommandManager, NopEmulatorExitHandler, (EdgeCoverageModule, (CmpLogModule, ())), StdState<MultipartInput<BytesInput>, CachedOnDiskCorpus<MultipartInput<BytesInput>>, libafl_bolts::prelude::RomuDuoJrRand, OnDiskCorpus<MultipartInput<BytesInput>>>>) -> SnapshotKind 
{
    let qemu = emulator.qemu();
    let cpu = qemu.first_cpu().unwrap();
    unsafe {
        SMM_INIT_FUZZ_EXIT_SNAPSHOT = ptr::null_mut();
        TIMEOUT_TIMES = 0;
        END_ERROR_TIMES = 0;
        CRASH_TIMES = 0;
        STREAM_OVER_TIMES = 0;
        ASSERT_TIMES = 0;
        NOTFOUND_TIMES = 0;
    }
    unskip();
    gen_init_random_seed(&seed_dirs);

    let (qemu_exit_reason, pc, cmd, sync_exit_reason, arg1, arg2) = qemu_run_once(qemu, &FuzzerSnapshot::new_empty(), 500000000,false, false);
    if cmd != LIBAFL_QEMU_COMMAND_END || sync_exit_reason != LIBAFL_QEMU_END_SMM_INIT_START {
        error!("init run to fuzz start error");
        exit_elegantly(ExitProcessType::Error);
    }
    let snapshot = FuzzerSnapshot::from_qemu(qemu);
    let try_snapshot = try_run_without_fuzz(qemu);
    if let SnapshotKind::None = try_snapshot {
        snapshot.restore_fuzz_snapshot(qemu, true);
    } else {
        snapshot.delete(qemu);
        return try_snapshot;
    }

    // skip();
    // let try_snapshot = try_run_without_fuzz(qemu);
    // if let SnapshotKind::None = try_snapshot {
    //     error!("cannot skip?");
    //     exit_elegantly(ExitProcessType::Ok);
    // } else {
    //     snapshot.delete(qemu);
    //     return try_snapshot;
    // }
    

    emulator.modules_mut().first_exec_all();
    let mut harness = |input: & MultipartInput<BytesInput>, state: &mut QemuExecutorState<_, _, _, _>| {
        let in_simulator = state.emulator_mut();
        let in_qemu: Qemu = in_simulator.qemu();
        let in_cpu = in_qemu.first_cpu().unwrap();
        let mut inputs = StreamInputs::from_multiinput(input);
        unsafe {  
            GLOB_INPUT = (&mut inputs) as *mut StreamInputs; 
        }
        let fuzz_input = unsafe {&mut (*GLOB_INPUT) };
        // set_fuzz_mem_switch(fuzz_input);
        
        let (qemu_exit_reason, pc, cmd, sync_exit_reason, arg1, arg2) = qemu_run_once(in_qemu, &snapshot, INIT_FUZZ_TIMEOUT_BBL,false, true);
        if let Ok(qemu_exit_reason) = qemu_exit_reason
        {
            if let QemuExitReason::SyncExit = qemu_exit_reason  {
                if cmd == LIBAFL_QEMU_COMMAND_END {
                    match sync_exit_reason {
                        LIBAFL_QEMU_END_SMM_INIT_ERROR | LIBAFL_QEMU_END_SMM_ASSERT => {
                            unsafe {
                                END_ERROR_TIMES += 1;
                            }
                        },
                        LIBAFL_QEMU_END_SMM_INIT_UNSUPPORT => {
                            unsafe {
                                NOTFOUND_TIMES += 1;
                            }
                        },
                        LIBAFL_QEMU_END_SMM_INIT_END => {
                            unsafe {
                                if SMM_INIT_FUZZ_EXIT_SNAPSHOT.is_null() {
                                    let box_snap = Box::new(FuzzerSnapshot::from_qemu(in_qemu));
                                    SMM_INIT_FUZZ_EXIT_SNAPSHOT = Box::into_raw(box_snap);
                                }
                            }
                        },
                        LIBAFL_QEMU_END_CRASH => {
                            unsafe {
                                CRASH_TIMES += 1;
                            }
                        },
                        _ => {
                            error!("exit sync_exit_reason {sync_exit_reason} pc:{}",get_readable_addr(pc));
                        },
                    }
                }
                else {
                    error!("exit cmd {cmd} {pc:#x}");
                }
            }
            else if let QemuExitReason::Timeout = qemu_exit_reason {
                unsafe {
                    TIMEOUT_TIMES += 1;
                }
            }
            else if let QemuExitReason::StreamNotFound = qemu_exit_reason {
            }
            else if let QemuExitReason::StreamOutof = qemu_exit_reason {
                unsafe {
                    STREAM_OVER_TIMES += 1;
                }
            }
            else if let QemuExitReason::Crash = qemu_exit_reason {
                unsafe {
                    CRASH_TIMES += 1;
                }
            }
            else if let QemuExitReason::End(_) = qemu_exit_reason {
                error!("Ctrl+C");
            }
            else if let QemuExitReason::Breakpoint(_) = qemu_exit_reason {
                error!("exit Breakpoint");
            }
            else {
                error!("exit unknown");
            }
        }
        else    {
            error!("exit {:?}",qemu_exit_reason);
        }
        ExitKind::Ok
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
        SmiGlobalFoundTimeMetadataFeedback::new(),
    );
    
    let mut objective = ();

    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        CachedOnDiskCorpus::<MultipartInput<BytesInput>>::new(corpus_dir.clone(),10 * 4096).unwrap(),
        OnDiskCorpus::<MultipartInput<BytesInput>>::new(objective_dir.clone()).unwrap(),
        &mut feedback,
        // Same for objective feedbacks
        &mut objective,
    ).unwrap();

    let mon = SimpleMonitor::new(|s| 
        info!("{s} crash:{} timeout:{} stream:{} unsupport:{} error:{}",unsafe{CRASH_TIMES}, unsafe {TIMEOUT_TIMES},unsafe{STREAM_OVER_TIMES}, unsafe {NOTFOUND_TIMES}, unsafe{END_ERROR_TIMES})  
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
            .load_initial_inputs_forced(&mut fuzzer, &mut executor, &mut mgr, &[seed_dirs.clone()])
            .unwrap_or_else(|_| {
                error!("Failed to load initial corpus at {:?}", &seed_dirs);
                exit_elegantly(ExitProcessType::Error);
            });
            info!("We imported {} inputs from disk.", state.corpus().count());
    }


    let havoc_stage = StdMutationalStage::new(StdScheduledMutator::new(havoc_mutations().merge(tokens_mutations())));
    let mut shadow_executor = ShadowExecutor::new(executor, tuple_list!(cmplog_observer));
    let i2s = StdMutationalStage::new(StdScheduledMutator::new(tuple_list!(
        I2SRandReplace::new()
    )));

    let mut stages = tuple_list!(ShadowTracingStage::new(&mut shadow_executor),i2s, havoc_stage);


    loop {
        fuzzer
            .fuzz_one(&mut stages, &mut shadow_executor, &mut state, &mut mgr)
            .unwrap();
        mgr.maybe_report_progress(&mut state, Duration::from_secs(20));
        if ctrlc_pressed() {
            exit_elegantly(ExitProcessType::Ok);
        }
        if libafl_bolts::current_time().as_secs() - state.last_found_time().as_secs() > unsafe { INIT_FUZZ_TIMEOUT_TIME } {
            skip();
            let dummy_testcase = state.corpus().get(state.corpus().last().unwrap()).unwrap().clone().take().clone().input().clone().unwrap();
            fuzzer.execute_input(&mut state, &mut shadow_executor, &mut mgr, &dummy_testcase);
        }
        if unsafe { !SMM_INIT_FUZZ_EXIT_SNAPSHOT.is_null() } {
            let exit_snapshot = unsafe { Box::from_raw(SMM_INIT_FUZZ_EXIT_SNAPSHOT) };
            // unsafe {
            //     if CURRENT_MODULE.eq(&uuid!("42293093-76b9-4482-8c02-3befdea9b35d")) {
            //         DEBUG_TRACE_TEST = true;
            //         info!("aaaaaaaaaaaaa");
            //     }
            // }
            let (qemu_exit_reason, pc, cmd, sync_exit_reason, arg1, arg2) = qemu_run_once(qemu, &exit_snapshot,8000000000, true, false);
            if let Ok(ref qemu_exit_reason) = qemu_exit_reason {
                if let QemuExitReason::SyncExit = qemu_exit_reason {
                    if cmd == LIBAFL_QEMU_COMMAND_END {
                        if sync_exit_reason == LIBAFL_QEMU_END_SMM_INIT_PREPARE {
                            exit_snapshot.delete(qemu);
                            snapshot.delete(qemu);
                            return SnapshotKind::StartOfSmmInitSnap(FuzzerSnapshot::new_empty());
                        }
                        else if sync_exit_reason == LIBAFL_QEMU_END_SMM_MODULE_START {
                            exit_snapshot.delete(qemu);
                            snapshot.delete(qemu);
                            return SnapshotKind::StartOfSmmModuleSnap(FuzzerSnapshot::new_empty());
                        }
                    }
                }
            }
            // if cmd == LIBAFL_QEMU_COMMAND_END && sync_exit_reason == LIBAFL_QEMU_END_CRASH {
            //     let mut rsp_data_buf : [u8; 8] = [0 ; 8];
            //     unsafe {
            //         cpu.read_mem(arg2,&mut rsp_data_buf);
            //     }
            //     let rsp_data = u64::from_le_bytes(rsp_data_buf);
            //     error!("fuzz one module over, run to next module error {:?} pc:{} cmd:{} sync_exit_reason:{} rsp:{:#x} [rsp]:{}",qemu_exit_reason,get_readable_addr(arg1), cmd, sync_exit_reason, arg2, get_readable_addr(rsp_data));
            // } else {
            //     error!("fuzz one module over, run to next module error {:?} pc:{} cmd:{} sync_exit_reason:{}",qemu_exit_reason,get_readable_addr(pc), cmd, sync_exit_reason);
            // }
            exit_snapshot.delete(qemu);
            unsafe {
                SMM_INIT_FUZZ_EXIT_SNAPSHOT = ptr::null_mut();
            }
            

        }
    }
    unreachable!();

}



pub fn init_phase_run(corpus_dir : PathBuf, emulator: &mut Emulator<NopCommandManager, NopEmulatorExitHandler, (), StdState<MultipartInput<BytesInput>, InMemoryCorpus<MultipartInput<BytesInput>>, libafl_bolts::prelude::RomuDuoJrRand, InMemoryCorpus<MultipartInput<BytesInput>>>>) -> Vec<(u128, usize)>
{
    let qemu = emulator.qemu();
    let cpu = qemu.first_cpu().unwrap();
    let snapshot = FuzzerSnapshot::from_qemu(qemu);
    unsafe {
        SMM_INIT_FUZZ_EXIT_SNAPSHOT = ptr::null_mut();
        TIMEOUT_TIMES = 0;
        END_ERROR_TIMES = 0;
        CRASH_TIMES = 0;
        STREAM_OVER_TIMES = 0;
        ASSERT_TIMES = 0;
        NOTFOUND_TIMES = 0;
    }
    
    let (qemu_exit_reason, pc, cmd, sync_exit_reason, arg1, arg2) = qemu_run_once(qemu, &FuzzerSnapshot::new_empty(), 500000000,false, false);
    if cmd != LIBAFL_QEMU_COMMAND_END || sync_exit_reason != LIBAFL_QEMU_END_SMM_INIT_START {
        error!("init run to fuzz start error");
        exit_elegantly(ExitProcessType::Error);
    }
    
    let snapshot = FuzzerSnapshot::from_qemu(qemu);
    let _ = try_run_without_fuzz(qemu);
    snapshot.restore_fuzz_snapshot(qemu, true);

    emulator.modules_mut().first_exec_all();
    let mut harness = |input: & MultipartInput<BytesInput>, state: &mut QemuExecutorState<_, _, _, _>| {
        let in_simulator = state.emulator_mut();
        let in_qemu: Qemu = in_simulator.qemu();
        let in_cpu = in_qemu.first_cpu().unwrap();
        let mut inputs = StreamInputs::from_multiinput(input);
        unsafe {  
            GLOB_INPUT = (&mut inputs) as *mut StreamInputs; 
        }
        let fuzz_input = unsafe {&mut (*GLOB_INPUT) };
        // set_fuzz_mem_switch(fuzz_input);

        
        let (qemu_exit_reason, pc, cmd, sync_exit_reason, arg1, arg2) = qemu_run_once(in_qemu, &snapshot, INIT_FUZZ_TIMEOUT_BBL,false, true);
        if let Ok(qemu_exit_reason) = qemu_exit_reason
        {
            if let QemuExitReason::SyncExit = qemu_exit_reason  {
                if cmd == LIBAFL_QEMU_COMMAND_END {
                    match sync_exit_reason {
                        LIBAFL_QEMU_END_SMM_INIT_ERROR | LIBAFL_QEMU_END_SMM_ASSERT => {
                            unsafe {
                                END_ERROR_TIMES += 1;
                            }
                        },
                        LIBAFL_QEMU_END_SMM_INIT_UNSUPPORT => {
                            unsafe {
                                NOTFOUND_TIMES += 1;
                            }
                        },
                        LIBAFL_QEMU_END_SMM_INIT_END => {
                            unsafe {
                                if SMM_INIT_FUZZ_EXIT_SNAPSHOT.is_null() {
                                    let box_snap = Box::new(FuzzerSnapshot::from_qemu(in_qemu));
                                    SMM_INIT_FUZZ_EXIT_SNAPSHOT = Box::into_raw(box_snap);
                                }
                            }
                        },
                        LIBAFL_QEMU_END_CRASH => {
                            unsafe {
                                CRASH_TIMES += 1;
                            }
                        },
                        _ => {
                            error!("exit sync_exit_reason {sync_exit_reason} pc:{}",get_readable_addr(pc));
                        },
                    }
                }
                else {
                    error!("exit cmd {cmd} {pc:#x}");
                }
            }
            else if let QemuExitReason::Timeout = qemu_exit_reason {
                unsafe {
                    TIMEOUT_TIMES += 1;
                }
            }
            else if let QemuExitReason::StreamNotFound = qemu_exit_reason {
            }
            else if let QemuExitReason::StreamOutof = qemu_exit_reason {
            }
            else if let QemuExitReason::Crash = qemu_exit_reason {
                unsafe {
                    CRASH_TIMES += 1;
                }
            }
            else if let QemuExitReason::End(_) = qemu_exit_reason {
                error!("Ctrl+C");
            }
            else if let QemuExitReason::Breakpoint(_) = qemu_exit_reason {
                error!("exit Breakpoint");
            }
            else {
                error!("exit unknown");
            }
        }
        else    {
            error!("exit {:?}",qemu_exit_reason);
        }
        
            
        ExitKind::Ok
    };

    let mut feedback = ();
    let mut objective = ();
    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        InMemoryCorpus::<MultipartInput<BytesInput>>::new(),
        InMemoryCorpus::<MultipartInput<BytesInput>>::new(),
        &mut feedback,
        // Same for objective feedbacks
        &mut objective,
    ).unwrap();

    let mon = SimpleMonitor::new(|s| 
        info!("{s}")  
    );
    let mut mgr = SimpleEventManager::new(mon);
    let scheduler = QueueScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);


    let mut executor = StatefulQemuExecutor::new(
        emulator,
        &mut harness,
        tuple_list!(),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        Duration::from_secs(100000),
    )
    .expect("Failed to create QemuExecutor");


    let mut ret = Vec::new();

    let mut corpus_inputs = Vec::new();
    if let Ok(entries) = fs::read_dir(corpus_dir.clone()) {
        for entry in entries {
            if let Ok(entry) = entry {
                let file_name = entry.file_name();
                let file_name_str = file_name.to_string_lossy();
                if !file_name_str.starts_with('.') {
                    let metadata_filename = format!(".{file_name_str}.metadata");
                    let metadata_fullpath = entry.path().parent().unwrap().join(metadata_filename);
                    corpus_inputs.push((entry.path().to_str().unwrap().to_string() , metadata_fullpath.to_str().unwrap().to_string(), 0));
                }
            }
        }
    }

    for input in corpus_inputs.iter_mut() {
        let contents = fs::read_to_string(input.1.clone()).unwrap();
        let config_json : Value = serde_json::from_str(&contents[..]).unwrap();
        let found_time = config_json.get("found_time").unwrap().as_str().unwrap().parse::<u128>().unwrap();
        input.2 = found_time;
    }
    corpus_inputs.sort_by( |a ,b| {
        a.2.cmp(&b.2)
    });
    for input in corpus_inputs.iter() {
        let input_testcase = MultipartInput::from_file(input.0.clone()).unwrap();
        fuzzer.execute_input(&mut state, &mut executor, &mut mgr, &input_testcase);
        ret.push((input.2, num_bbl_covered()));
        info!("bbl {} {}",input.2, num_bbl_covered());
    }
    snapshot.delete(qemu);
    return ret;

}