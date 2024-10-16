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
use std::env;
use crate::stream_input::*;
use crate::qemu_args::*;
use crate::common_hooks::*;
use crate::config::*;
use crate::exit_qemu::*;
use crate::fuzzer_snapshot::*;
use crate::qemu_control::*;


static mut SMM_INIT_FUZZ_EXIT_SNAPSHOT : *mut FuzzerSnapshot = ptr::null_mut();
static mut SMM_INIT_FUZZ_INDEX : u64 = 1;

fn gen_init_random_seed(corpus_dirs : &PathBuf) {
    let mut initial_input = MultipartInput::<BytesInput>::new();
    initial_input.add_part(0 as u128, BytesInput::new(DEFAULT_STREAM_DATA.to_vec()));
    let mut init_seed_path = PathBuf::new(); 
    init_seed_path.push(corpus_dirs.clone());
    init_seed_path.push(PathBuf::from("init.bin"));
    initial_input.to_file(init_seed_path).unwrap();
}


pub fn init_phase_fuzz<CM, EH, ET, S>(emulator: &mut Emulator<NopCommandManager, NopEmulatorExitHandler, (EdgeCoverageModule, ()), StdState<MultipartInput<BytesInput>, CachedOnDiskCorpus<MultipartInput<BytesInput>>, libafl_bolts::prelude::RomuDuoJrRand, CachedOnDiskCorpus<MultipartInput<BytesInput>>>>, snap : SnapshotKind) -> SnapshotKind 
{
    let qemu = emulator.qemu();
    let cpu = qemu.first_cpu().unwrap();
    let mut snapshot = FuzzerSnapshot::new_empty();
    if let SnapshotKind::StartOfSmmInitSnap(sss) = snap {
        snapshot = sss;
        snapshot.restore_fuzz_snapshot(emulator.qemu());
    }
    else {
        error!("init phase fuzz got non start of smm init snapshot");
        exit_elegantly();
    }
    unsafe {
        SMM_INIT_FUZZ_EXIT_SNAPSHOT = ptr::null_mut();

    }

    let corpus_dirs = [PathBuf::from(INIT_PHASE_CORPUS_DIR).join(PathBuf::from(format!("init_phase_corpus_{}/", unsafe {SMM_INIT_FUZZ_INDEX})))];
    let objective_dir = PathBuf::from(INIT_PHASE_SOLUTION_DIR).join(PathBuf::from(format!("init_phase_crash_{}/", unsafe {SMM_INIT_FUZZ_INDEX})));
    fs::create_dir_all(corpus_dirs[0].clone()).unwrap();
    fs::create_dir_all(objective_dir.clone()).unwrap();
    gen_init_random_seed(&corpus_dirs[0]);
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
        let exit_reason = qemu_run_once(in_qemu, &snapshot, 50000000);
        let exit_code;
        debug!("new run exit {:?}",exit_reason);
        if let Ok(qemu_exit_reason) = exit_reason
        {
            if let QemuExitReason::SyncExit = qemu_exit_reason  {
                let cmd : GuestReg = in_cpu.read_reg(Regs::Rax).unwrap();
                let arg1 : GuestReg = in_cpu.read_reg(Regs::Rdi).unwrap();
                let pc : GuestReg = in_cpu.read_reg(Regs::Rip).unwrap();
                debug!("qemu_run_to_end sync exit {:#x} {:#x} {:#x}",cmd,arg1,pc);
                if cmd == 4 {
                    match arg1 {
                        2 => {
                            exit_code = ExitKind::Crash;
                        },
                        4 => {
                            unsafe {
                                if SMM_INIT_FUZZ_EXIT_SNAPSHOT.is_null() {
                                    let box_snap = Box::new(FuzzerSnapshot::from_qemu(in_qemu));
                                    // info!("found the way to pass init function");
                                    SMM_INIT_FUZZ_EXIT_SNAPSHOT = Box::into_raw(box_snap);
                                }
                            }
                            exit_code = ExitKind::Ok;
                        },
                        _ => {
                            exit_elegantly();
                            exit_code = ExitKind::Ok;
                        }
                    }
                }
                else {
                    exit_elegantly();
                    exit_code = ExitKind::Ok;
                }
            }
            else if let QemuExitReason::Timeout = qemu_exit_reason {
                exit_code = ExitKind::Timeout;
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
    let stream_observer = StreamObserver::new("stream", unsafe {Arc::clone(&NEW_STREAM)});

    let mut feedback = feedback_or!(
        MaxMapFeedback::new(&edges_observer),
        TimeFeedback::new(&time_observer),
        StreamFeedback::new(&stream_observer),
    );
    
    // A feedback to choose if an input is a solution or not
    let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        CachedOnDiskCorpus::<MultipartInput<BytesInput>>::new(corpus_dirs[0].clone(),10 * 4096).unwrap(),
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
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &corpus_dirs)
            .unwrap_or_else(|_| {
                error!("Failed to load initial corpus at {:?}", &corpus_dirs);
                exit_elegantly();
            });
            info!("We imported {} inputs from disk.", state.corpus().count());
    }
    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    
    loop {
        if unsafe { !SMM_INIT_FUZZ_EXIT_SNAPSHOT.is_null() } {
            let exit_snapshot = unsafe { Box::from_raw(SMM_INIT_FUZZ_EXIT_SNAPSHOT) };
            let exit_reason = qemu_run_once(qemu, &exit_snapshot,30000000);
            let cmd : GuestReg = cpu.read_reg(Regs::Rax).unwrap();
            let arg1 : GuestReg = cpu.read_reg(Regs::Rdi).unwrap();
            if let Ok(ref qemu_exit_reason) = exit_reason {
                if let QemuExitReason::SyncExit = qemu_exit_reason {
                    if cmd == 4 {
                        if arg1 == 3 {
                            // snapshot.delete(qemu);
                            return SnapshotKind::StartOfSmmInitSnap(FuzzerSnapshot::from_qemu(qemu));
                        }
                        else if arg1 == 5 {
                            // snapshot.delete(qemu);
                            return SnapshotKind::StartOfSmmFuzzSnap(FuzzerSnapshot::from_qemu(qemu));
                        }
                    }
                    
                }
            }
            unsafe {
                exit_snapshot.delete(qemu);
                SMM_INIT_FUZZ_EXIT_SNAPSHOT = ptr::null_mut();
            }
            warn!("smm init found {:?} {cmd:#x} {arg1:#x}",exit_reason);
        }
        fuzzer
            .fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr)
            .unwrap();
    }
    
    exit_elegantly();
    SnapshotKind::None

}