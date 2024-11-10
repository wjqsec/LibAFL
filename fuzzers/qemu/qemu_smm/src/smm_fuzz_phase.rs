use core::{ptr::addr_of_mut, time::Duration};
use std::cell::UnsafeCell;
use std::fmt::format;
use std::{path::PathBuf, process};
use libafl_bolts::math;
use log::*;
use std::ptr;
use libafl::{
    corpus::Corpus, executors::ExitKind, feedback_or, feedback_or_fast, feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback}, fuzzer::{Fuzzer, StdFuzzer}, inputs::{BytesInput, Input}, mutators::scheduled::{havoc_mutations, StdScheduledMutator}, observers::{stream::StreamObserver, CanTrack, HitcountsMapObserver, TimeObserver, VariableMapObserver}, prelude::{powersched::PowerSchedule, CachedOnDiskCorpus, PowerQueueScheduler, SimpleEventManager, SimpleMonitor}, stages::StdMutationalStage, state::{HasCorpus, StdState}
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
        edges_map_mut_ptr, EdgeCoverageModule, EDGES_MAP_SIZE_IN_USE, MAX_EDGES_FOUND,
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

static mut TIMEOUT_TIMES : u64 = 0;
static mut END_TIMES : u64 = 0;
static mut CRASH_TIMES : u64 = 0;
static mut STREAM_OVER_TIMES : u64 = 0;

fn gen_init_random_seed(dir : &PathBuf) {
    let mut initial_input = MultipartInput::<BytesInput>::new();
    initial_input.add_part(0 as u128, BytesInput::new(DEFAULT_STREAM_DATA.to_vec()), 0x10);
    let mut init_seed_path = PathBuf::new(); 
    init_seed_path.push(dir.clone());
    init_seed_path.push(PathBuf::from("init.bin"));
    initial_input.to_file(init_seed_path).unwrap();
}

fn run_to_smm_fuzz_point(qemu : Qemu, cpu : CPU, start_snapshot : &FuzzerSnapshot) -> FuzzerSnapshot {
    // run to the start cause we are now at the start of the smm fuzz driver
    let mut exit_reason = qemu_run_once(qemu, start_snapshot,10000000000, true, false);
    let cmd : GuestReg = cpu.read_reg(Regs::Rax).unwrap();
    let arg1 : GuestReg = cpu.read_reg(Regs::Rdi).unwrap();
    if let Ok(ref qemu_exit_reason) = exit_reason {
        if let QemuExitReason::SyncExit = qemu_exit_reason {
            if cmd == LIBAFL_QEMU_COMMAND_END {
                if arg1 == LIBAFL_QEMU_END_SMM_FUZZ_START {
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
    return FuzzerSnapshot::new_empty();
}


pub fn smm_phase_fuzz(emulator: &mut Emulator<NopCommandManager, NopEmulatorExitHandler, (EdgeCoverageModule, (CmpLogModule, ())), StdState<MultipartInput<BytesInput>, CachedOnDiskCorpus<MultipartInput<BytesInput>>, libafl_bolts::prelude::RomuDuoJrRand, CachedOnDiskCorpus<MultipartInput<BytesInput>>>>, snapshot : &FuzzerSnapshot) -> SnapshotKind 
{
    let qemu = emulator.qemu();
    let cpu: CPU = qemu.first_cpu().unwrap();
    let corpus_dir = PathBuf::from(INIT_PHASE_CORPUS_DIR).join(PathBuf::from(format!("smm_phase_corpus_fuzz/")));
    let objective_dir = PathBuf::from(INIT_PHASE_SOLUTION_DIR).join(PathBuf::from(format!("smm_phase_crash_fuzz/")));
    let seed_dirs = [PathBuf::from(INIT_PHASE_SEED_DIR).join(PathBuf::from(format!("smm_phase_seed_fuzz/")))];
    fs::create_dir_all(corpus_dir.clone()).unwrap();
    fs::create_dir_all(objective_dir.clone()).unwrap();
    fs::create_dir_all(seed_dirs[0].clone()).unwrap();
    gen_init_random_seed(&seed_dirs[0]);

    let smi_fuzz_snapshot = run_to_smm_fuzz_point(qemu, cpu, snapshot);

    let mut harness = |input: & MultipartInput<BytesInput>, state: &mut QemuExecutorState<_, _, _, _>| {
        
        debug!("new run");
        let mut inputs = StreamInputs::from_multiinput(input);
        unsafe {  
            GLOB_INPUT = (&mut inputs) as *mut StreamInputs;
        }
        let in_simulator = state.emulator_mut();
        let in_qemu: Qemu = in_simulator.qemu();
        let in_cpu = in_qemu.first_cpu().unwrap();
        let exit_reason = qemu_run_once(in_qemu, &smi_fuzz_snapshot, 50000000,false, true);
        let exit_code;
        debug!("new run exit {:?}",exit_reason);
        if let Ok(qemu_exit_reason) = exit_reason
        {
            if let QemuExitReason::SyncExit = qemu_exit_reason  {
                let cmd : GuestReg = in_cpu.read_reg(Regs::Rax).unwrap();
                let arg1 : GuestReg = in_cpu.read_reg(Regs::Rdi).unwrap();
                let pc : GuestReg = in_cpu.read_reg(Regs::Rip).unwrap();
                debug!("qemu_run_to_end sync exit {:#x} {:#x} {:#x}",cmd,arg1,pc);
                if cmd == LIBAFL_QEMU_COMMAND_END {
                    match arg1 {
                        LIBAFL_QEMU_END_CRASH => {
                            unsafe {TIMEOUT_TIMES += 1;}
                            exit_code = ExitKind::Crash;
                        },
                        LIBAFL_QEMU_END_SMM_FUZZ_END => {
                            unsafe {END_TIMES += 1;}
                            exit_code = ExitKind::Ok;
                        },
                        _ => {
                            error!("exit error with sync exit arg {:#x}",arg1);
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
    let mut objective = feedback_or_fast!(CrashFeedback::new());

    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        CachedOnDiskCorpus::<MultipartInput<BytesInput>>::new(corpus_dir.clone(),10 * 4096).unwrap(),
        CachedOnDiskCorpus::<MultipartInput<BytesInput>>::new(objective_dir,10 * 4096).unwrap(),
        &mut feedback,
        // Same for objective feedbacks
        &mut objective,
    ).unwrap();

    let mon = SimpleMonitor::new(|s| 
        info!("{s} end:{:?} stream:{:?} crash:{:?} timeout:{:?}",unsafe{END_TIMES}, unsafe{STREAM_OVER_TIMES}, unsafe{CRASH_TIMES}, unsafe{TIMEOUT_TIMES})  
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

    
    fuzzer
            .fuzz_loop(&mut stages, &mut shadow_executor, &mut state, &mut mgr)
            .unwrap();
    SnapshotKind::None

}