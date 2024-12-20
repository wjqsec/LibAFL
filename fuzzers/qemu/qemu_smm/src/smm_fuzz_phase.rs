use core::{ptr::addr_of_mut, time::Duration};
use std::cell::UnsafeCell;
use std::fmt::format;
use std::str::FromStr;
use std::{path::PathBuf, process};
use libafl::corpus::{HasCurrentCorpusId, HasTestcase};
use libafl::state::HasSolutions;
use libafl_bolts::math;
use log::*;
use std::ptr;
use libafl::prelude::InMemoryCorpus;
use libafl::{
    corpus::Corpus, executors::ExitKind, feedback_or, feedback_or_fast, feedbacks::{AflMapFeedback, CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback}, fuzzer::{Fuzzer, StdFuzzer}, inputs::{BytesInput, Input}, mutators::scheduled::{havoc_mutations, StdScheduledMutator}, observers::{stream::StreamObserver, CanTrack, HitcountsMapObserver, TimeObserver, VariableMapObserver}, prelude::{powersched::PowerSchedule, OnDiskCorpus, CachedOnDiskCorpus, PowerQueueScheduler, QueueScheduler, SimpleEventManager, SimpleMonitor}, stages::StdMutationalStage, state::{HasCorpus, StdState}
};
use libafl::mutators::Tokens;
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
use libafl::{ExecutesInput, HasMetadata, HasObjective};
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
use crate::exit_qemu::*;
use crate::coverage::*;
use crate::fuzzer_snapshot::*;
use crate::qemu_control::*;
use crate::cmd::*;
use crate::smm_fuzz_qemu_cmds::*;

static mut TIMEOUT_TIMES : u64 = 0;
static mut END_TIMES : u64 = 0;
static mut CRASH_TIMES : u64 = 0;
static mut STREAM_OVER_TIMES : u64 = 0;
static mut ASSERT_TIMES : u64 = 0;
fn gen_init_random_seed(dir : &PathBuf) {
    let mut initial_input = MultipartInput::<BytesInput>::new();
    initial_input.add_part(0 as u128, BytesInput::new(vec![]), 0x10, 0);
    let mut init_seed_path = PathBuf::new(); 
    init_seed_path.push(dir.clone());
    init_seed_path.push(PathBuf::from("init.bin"));
    initial_input.to_file(init_seed_path).unwrap();
}
fn add_uefi_fuzz_token(state : &mut StdState<MultipartInput<BytesInput>, CachedOnDiskCorpus<MultipartInput<BytesInput>>, libafl_bolts::prelude::RomuDuoJrRand, OnDiskCorpus<MultipartInput<BytesInput>>>) {
    let mut tokens = Tokens::new();

    for i in 0..10 {
        tokens.add_token(&(i as u8).to_le_bytes().to_vec());
        tokens.add_token(&(i as u16).to_le_bytes().to_vec());
        tokens.add_token(&(i as u32).to_le_bytes().to_vec());
        tokens.add_token(&(i as u64).to_le_bytes().to_vec());
    }

    state.add_metadata(tokens);
}

fn run_to_smm_fuzz_point(qemu : Qemu, cpu : CPU) -> FuzzerSnapshot {
    // run to the start cause we are now at the start of the smm fuzz driver
    let (qemu_exit_reason, pc, cmd, sync_exit_reason, arg1, arg2) = qemu_run_once(qemu, &FuzzerSnapshot::new_empty(),10000000000, true, false);
    if let Ok(ref qemu_exit_reason) = qemu_exit_reason {
        if let QemuExitReason::SyncExit = qemu_exit_reason {
            if cmd == LIBAFL_QEMU_COMMAND_END {
                if sync_exit_reason == LIBAFL_QEMU_END_SMM_FUZZ_START {
                    return FuzzerSnapshot::from_qemu(qemu);
                }
                else {
                    error!("got error while going to the smi fuzz point");
                    exit_elegantly();
                }
            }
        } else if let QemuExitReason::End(_) = qemu_exit_reason {
            error!("got error while going to the smi fuzz point");
            exit_elegantly();
        }
    }
    error!("got error while going to the smi fuzz point");
    exit_elegantly();
    return FuzzerSnapshot::new_empty();
}


pub fn smm_phase_fuzz(seed_dirs : PathBuf, corpus_dir : PathBuf, objective_dir : PathBuf, emulator: &mut Emulator<NopCommandManager, NopEmulatorExitHandler, (EdgeCoverageModule, (CmpLogModule, ())), StdState<MultipartInput<BytesInput>, CachedOnDiskCorpus<MultipartInput<BytesInput>>, libafl_bolts::prelude::RomuDuoJrRand, OnDiskCorpus<MultipartInput<BytesInput>>>>)
{
    let qemu = emulator.qemu();
    let cpu: CPU = qemu.first_cpu().unwrap();
    gen_init_random_seed(&seed_dirs);

    let smi_fuzz_snapshot = run_to_smm_fuzz_point(qemu, cpu);

    let mut harness = |input: & MultipartInput<BytesInput>, state: &mut QemuExecutorState<_, _, _, _>| {
        let mut inputs = StreamInputs::from_multiinput(input);
        unsafe {  
            GLOB_INPUT = (&mut inputs) as *mut StreamInputs;
            IN_SMI = false;
        }
        let in_simulator = state.emulator_mut();
        let in_qemu: Qemu = in_simulator.qemu();
        let in_cpu = in_qemu.first_cpu().unwrap();
        let (qemu_exit_reason, pc, cmd, sync_exit_reason, arg1, arg2) = qemu_run_once(in_qemu, &smi_fuzz_snapshot, 50000,false, true);
        let exit_code;
        debug!("new run exit {:?}",qemu_exit_reason);
        if let Ok(qemu_exit_reason) = qemu_exit_reason
        {
            if let QemuExitReason::SyncExit = qemu_exit_reason  {
                debug!("qemu_run_to_end sync exit {:#x} {:#x} {:#x}",cmd,sync_exit_reason,pc);
                if cmd == LIBAFL_QEMU_COMMAND_END {
                    match sync_exit_reason {
                        LIBAFL_QEMU_END_CRASH => {
                            unsafe {CRASH_TIMES += 1;}
                            exit_code = ExitKind::Crash;
                        },
                        LIBAFL_QEMU_END_SMM_FUZZ_END => {
                            unsafe {END_TIMES += 1;}
                            exit_code = ExitKind::Ok;
                        },
                        | LIBAFL_QEMU_END_SMM_ASSERT => {
                            unsafe {ASSERT_TIMES += 1;}
                            exit_code = ExitKind::Ok;
                        },
                        _ => {
                            error!("exit error with sync exit arg {:#x}",sync_exit_reason);
                            exit_elegantly();
                            exit_code = ExitKind::Ok;
                        }
                    }
                }
                else {
                    error!("exit error with sync exit cmd {:#x}",cmd);
                    exit_elegantly();
                    exit_code = ExitKind::Ok;
                }
            }
            else if let QemuExitReason::Timeout = qemu_exit_reason {
                unsafe {TIMEOUT_TIMES += 1;}
                exit_code = ExitKind::Timeout;
            }
            else if let QemuExitReason::StreamNotFound = qemu_exit_reason {
                exit_code = ExitKind::Ok;
            }
            else if let QemuExitReason::StreamOutof = qemu_exit_reason {
                unsafe {STREAM_OVER_TIMES += 1;}
                exit_code = ExitKind::Ok;
            }
            else if let QemuExitReason::End(_) = qemu_exit_reason {
                error!("ctrl-C");
                exit_elegantly();
                exit_code = ExitKind::Ok;
            }
            else if let QemuExitReason::Breakpoint(_) = qemu_exit_reason {
                error!("Unexpected breakpoint hit");
                exit_elegantly();
                exit_code = ExitKind::Ok;
            }
            else {
                error!("Unexpected exit");
                exit_elegantly();
                exit_code = ExitKind::Ok;
            }
        }
        else    {
            error!("Unexpected exit");
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
    let mut objective = feedback_or!(
        CrashFeedback::new(),
        StreamFeedback::new(&stream_observer)
    );

    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        CachedOnDiskCorpus::<MultipartInput<BytesInput>>::new(corpus_dir.clone(),10 * 4096).unwrap(),
        OnDiskCorpus::<MultipartInput<BytesInput>>::new(objective_dir.clone()).unwrap(),
        &mut feedback,
        // Same for objective feedbacks
        &mut objective,
    ).unwrap();
    add_uefi_fuzz_token(&mut state);

    let mon = SimpleMonitor::new(|s| 
        info!("{s} bbl:{:?} end:{:?} stream:{:?} crash:{:?} timeout:{:?} assert:{:?}",num_bbl_covered(), unsafe{END_TIMES}, unsafe{STREAM_OVER_TIMES}, unsafe{CRASH_TIMES}, unsafe{TIMEOUT_TIMES}, unsafe{ASSERT_TIMES})  
    );
    let mut mgr = SimpleEventManager::new(mon);
    // let scheduler = PowerQueueScheduler::new(&mut state, &mut edges_observer, PowerSchedule::FAST);
    let scheduler = QueueScheduler::new();
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
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &[seed_dirs.clone()])
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
        fuzzer.fuzz_one(&mut stages, &mut shadow_executor, &mut state, &mut mgr).unwrap();
    }

}


pub fn smm_phase_run(input : RunMode, emulator: &mut Emulator<NopCommandManager, NopEmulatorExitHandler, (), StdState<MultipartInput<BytesInput>, InMemoryCorpus<MultipartInput<BytesInput>>, libafl_bolts::prelude::RomuDuoJrRand, InMemoryCorpus<MultipartInput<BytesInput>>>>)
{
    let qemu = emulator.qemu();
    let cpu: CPU = qemu.first_cpu().unwrap();

    let smi_fuzz_snapshot = run_to_smm_fuzz_point(qemu, cpu);

    let mut harness = |input: & MultipartInput<BytesInput>, state: &mut QemuExecutorState<_, _, _, _>| {
        let mut inputs = StreamInputs::from_multiinput(input);
        unsafe {  
            GLOB_INPUT = (&mut inputs) as *mut StreamInputs;
            IN_SMI = false;
        }
        let in_simulator = state.emulator_mut();
        let in_qemu: Qemu = in_simulator.qemu();
        let in_cpu = in_qemu.first_cpu().unwrap();
        let (qemu_exit_reason, pc, cmd, sync_exit_reason, arg1, arg2) = qemu_run_once(in_qemu, &smi_fuzz_snapshot, 2000000,false, true);
        let exit_code;
        info!("new run exit {:?}",qemu_exit_reason);
        if let Ok(qemu_exit_reason) = qemu_exit_reason
        {
            if let QemuExitReason::SyncExit = qemu_exit_reason  {
                info!("qemu_run_to_end sync exit {:#x} {:#x} {:#x}",cmd,sync_exit_reason,pc);
                if cmd == LIBAFL_QEMU_COMMAND_END {
                    match sync_exit_reason {
                        LIBAFL_QEMU_END_CRASH => {
                            unsafe {CRASH_TIMES += 1;}
                            exit_code = ExitKind::Crash;
                        },
                        LIBAFL_QEMU_END_SMM_FUZZ_END => {
                            unsafe {END_TIMES += 1;}
                            exit_code = ExitKind::Ok;
                        },
                        | LIBAFL_QEMU_END_SMM_ASSERT => {
                            unsafe {ASSERT_TIMES += 1;}
                            exit_code = ExitKind::Ok;
                        },
                        _ => {
                            error!("exit error with sync exit arg {:#x}",sync_exit_reason);
                            exit_elegantly();
                            exit_code = ExitKind::Ok;
                        }
                    }
                }
                else {
                    error!("exit error with sync exit cmd {:#x}",cmd);
                    exit_elegantly();
                    exit_code = ExitKind::Ok;
                }
            }
            else if let QemuExitReason::Timeout = qemu_exit_reason {
                unsafe {TIMEOUT_TIMES += 1;}
                exit_code = ExitKind::Timeout;
            }
            else if let QemuExitReason::StreamNotFound = qemu_exit_reason {
                exit_code = ExitKind::Ok;
            }
            else if let QemuExitReason::StreamOutof = qemu_exit_reason {
                unsafe {STREAM_OVER_TIMES += 1;}
                exit_code = ExitKind::Ok;
            }
            else if let QemuExitReason::End(_) = qemu_exit_reason {
                error!("ctrl-C");
                exit_elegantly();
                exit_code = ExitKind::Ok;
            }
            else if let QemuExitReason::Breakpoint(_) = qemu_exit_reason {
                error!("Unexpected breakpoint hit");
                exit_elegantly();
                exit_code = ExitKind::Ok;
            }
            else {
                error!("Unexpected exit");
                exit_elegantly();
                exit_code = ExitKind::Ok;
            }
        }
        else    {
            error!("Unexpected exit");
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
    let mut feedback = feedback_or!(
        MaxMapFeedback::new(&edges_observer),
        TimeFeedback::new(&time_observer),
        StreamFeedback::new(&stream_observer),
    );
    
    // A feedback to choose if an input is a solution or not
    let mut objective = feedback_or_fast!(CrashFeedback::new());

    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        InMemoryCorpus::<MultipartInput<BytesInput>>::new(),
        InMemoryCorpus::<MultipartInput<BytesInput>>::new(),
        &mut feedback,
        // Same for objective feedbacks
        &mut objective,
    ).unwrap();

    let mon = SimpleMonitor::new(|s| 
        info!("{s} bbl:{:?} end:{:?} stream:{:?} crash:{:?} timeout:{:?} assert:{:?}",num_bbl_covered(), unsafe{END_TIMES}, unsafe{STREAM_OVER_TIMES}, unsafe{CRASH_TIMES}, unsafe{TIMEOUT_TIMES}, unsafe{ASSERT_TIMES})  
    );
    let mut mgr = SimpleEventManager::new(mon);
    // let scheduler = PowerQueueScheduler::new(&mut state, &mut edges_observer, PowerSchedule::FAST);
    let scheduler = QueueScheduler::new();
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
    unsafe {
        IN_SMI_FUZZ_PHASE = true;
    }

    match input {
        RunMode::RunCopus(corpus) => {
            state.load_initial_inputs_forced(&mut fuzzer, &mut executor, &mut mgr, &[corpus]);
        },
        RunMode::RunTestcase(testcase) => {
            state.load_initial_inputs_by_filenames_forced(&mut fuzzer, &mut executor, &mut mgr, &[testcase]);
        },
    }
}
