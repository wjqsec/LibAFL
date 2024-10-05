use core::{ptr::addr_of_mut, time::Duration};
use std::borrow::Borrow;
use std::cell::UnsafeCell;
use std::mem::transmute;
use std::str::FromStr;
use std::{cell::RefCell, collections::HashMap, env, fmt::format, path::PathBuf, process, rc::Rc, vec};
use std::ptr::copy;
use rand::Rng;
use std::slice;
use std::process::{Command, exit};
use log::*;
use libafl::{
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus}, events::{launcher::Launcher, EventConfig}, executors::ExitKind, feedback_or, feedback_or_fast, feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback}, fuzzer::{Fuzzer, StdFuzzer}, inputs::{BytesInput, HasMutatorBytes, HasTargetBytes, Input}, monitors::MultiMonitor, mutators::scheduled::{havoc_mutations, StdScheduledMutator}, observers::{stream::StreamObserver, CanTrack, HitcountsMapObserver, TimeObserver, VariableMapObserver}, prelude::{powersched::PowerSchedule, CachedOnDiskCorpus, IfStage, PowerQueueScheduler, SimpleEventManager, SimpleMonitor}, schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler}, stages::StdMutationalStage, state::{HasCorpus, StdState}, Error
};
use libafl::prelude::{ColorizationStage,TracingStage};
use libafl::prelude::InMemoryOnDiskCorpus;
use libafl::state::HasCurrentTestcase;
use libafl_bolts::tuples::MatchNameRef;
use libafl::executors::inprocess::InProcessExecutor;
use libafl::feedbacks::stream::StreamFeedback;
use libafl_qemu::modules::cmplog::CmpLogObserver;
use libafl::inputs::multi::MultipartInput;
use std::sync::{Arc, Mutex};
use libafl::stages::mutational::MultiMutationalStage;
use libafl::prelude::AFLppRedQueen;
use libafl_bolts::{
    core_affinity::Cores,
    current_nanos,
    os::unix_signals::{Signal, CTRL_C_EXIT},
    ownedref::OwnedMutSlice,
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::{tuple_list, Handled},
    AsSlice, AsSliceMut, HasLen,
};
use once_cell::sync::Lazy;
use libafl_qemu::{
    command::NopCommandManager, elf::EasyElf, executor::{stateful::StatefulQemuExecutor, QemuExecutorState}, modules::edges::{
        edges_map_mut_ptr, EdgeCoverageModule, EDGES_MAP_SIZE_IN_USE, MAX_EDGES_FOUND,
    }, Emulator, NopEmulatorExitHandler, PostDeviceregReadHookId, PreDeviceregWriteHookId, Qemu, QemuExitError, QemuExitReason, QemuRWError, QemuShutdownCause, Regs
};
use libafl_qemu_sys::GuestPhysAddr;
use libafl_qemu_sys::{CPUArchStatePtr, FatPtr, GuestAddr, GuestUsize};
use libafl_qemu::modules::cmplog::CmpLogModule;
use libafl_qemu::executor::QemuExecutor;
use libafl_qemu::Hook;
use libafl_qemu::modules::edges::gen_hashed_block_ids;
use libafl_qemu::GuestReg;
use libafl_qemu::qemu::BlockHookId;
use libafl_qemu::sync_exit::ExitArgs;
use libafl_qemu::CPU;
use libafl_qemu::SnapshotManager;
use libafl_qemu::QemuSnapshotManager;
use libafl_qemu::IsSnapshotManager;
use libafl_qemu::DeviceSnapshotFilter;
use libafl_qemu::QemuMemoryChunk;
use libafl_qemu::FastSnapshotPtr;
use crate::stream_input::*;
use crate::qemu_args::*;
use crate::common_hooks::*;
use crate::config::*;
use crate::exit_qemu::*;
static mut GLOB_INPUT : UnsafeCell<*mut StreamInputs> = UnsafeCell::new(std::ptr::null_mut() as *mut StreamInputs);
static mut EXEC_COUNT : UnsafeCell<u64> = UnsafeCell::new(0);
static NEW_STREAM : Lazy<Arc<Mutex<Vec<u128>>>> = Lazy::new( || Arc::new(Mutex::new(Vec::new())) );
static mut SMM_FUZZ_SNAPSHOT : UnsafeCell<Option<FastSnapshotPtr>> = UnsafeCell::new(None);



fn get_exec_count() -> u64  {
    let exec_count;
    unsafe { exec_count =  *EXEC_COUNT.get(); }
    exec_count
}
fn set_exec_count(val :u64) {
    unsafe { *EXEC_COUNT.get() =  val; }
}

fn gen_init_random_seed(corpus_dirs : &PathBuf) {
    let mut initial_input = MultipartInput::<BytesInput>::new();
    initial_input.add_part(0 as u128, BytesInput::new(DEFAULT_STREAM_DATA.to_vec()));
    let mut init_seed_path = PathBuf::new(); 
    init_seed_path.push(corpus_dirs.clone());
    init_seed_path.push(PathBuf::from("init.bin"));
    initial_input.to_file(init_seed_path).unwrap();
}

pub fn init_fuzz(qemu : Qemu) -> FastSnapshotPtr {
    let corpus_dirs = [PathBuf::from(INIT_PHASE_CORPUS_DIR)];
    let objective_dir = PathBuf::from(INIT_PHASE_SOLUTION_DIR);

    gen_init_random_seed(&corpus_dirs[0]);

    let mut emulator = Emulator::new_with_qemu(qemu,
        tuple_list!(EdgeCoverageModule::default()),
        NopEmulatorExitHandler,
        NopCommandManager)
        .unwrap();
    let cpu: CPU = qemu.first_cpu().unwrap();
    let dev_filter = DeviceSnapshotFilter::DenyList(get_snapshot_dev_filter_list());
    let snap = emulator.create_fast_snapshot_filter(true,&dev_filter);


    let block_id : BlockHookId = emulator.modules_mut().blocks(Hook::Function(gen_hashed_block_ids::<_, _>), Hook::Empty, 
    Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, id: u64| {
            let pc : GuestReg = cpu.read_reg(Regs::Pc).unwrap();
            let eax : GuestReg = cpu.read_reg(Regs::Rax).unwrap();
            let rdi : GuestReg = cpu.read_reg(Regs::Rdi).unwrap();
            trace!("bbl-> {pc:#x} {eax:#x} {rdi:#x}");
            if get_exec_count() > INIT_PHASE_NUM_TIMEOUT_BBL {
                cpu.exit_timeout();
            }
            set_exec_count(get_exec_count() + 1);
                
    })));
    let devread_id : PostDeviceregReadHookId = emulator.modules_mut().devread(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : u32| {
        let fuzz_input = unsafe {&mut (**GLOB_INPUT.get()) };
        let qemu: Qemu = modules.qemu();
        let pc : GuestReg = cpu.read_reg(Regs::Pc).unwrap();
        post_io_read_common(pc , base , offset ,size , data , handled,fuzz_input ,qemu);

    })));
    let devwrite_id : PreDeviceregWriteHookId = emulator.modules_mut().devwrite(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : *mut bool| {
        let pc : GuestReg = cpu.read_reg(Regs::Pc).unwrap();
        pre_io_write_common(pc, base, offset,size , data , handled);
    })));
    let memrw_id = emulator.modules_mut().memrw(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, pc : GuestAddr, addr : GuestAddr, size : u64, out_addr : *mut GuestAddr | {
        pre_memrw_common(pc, addr, size, out_addr);
    })));
    let backdoor_id = emulator.modules_mut().backdoor(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, addr : GuestAddr| {
        let qemu = modules.qemu();
        let pc : GuestReg = cpu.read_reg(Regs::Pc).unwrap();
        let cmd : GuestReg = cpu.read_reg(Regs::Rax).unwrap();
        let arg1 : GuestReg = cpu.read_reg(Regs::Rdi).unwrap();
        let arg2 : GuestReg = cpu.read_reg(Regs::Rsi).unwrap();
        let arg3 : GuestReg = cpu.read_reg(Regs::Rdx).unwrap();
        backdoor_common(qemu, cmd, arg1, arg2, arg3);
    })));

    let mut harness = |input: & MultipartInput<BytesInput>, state: &mut QemuExecutorState<_, _, _, _>| {
        debug!("new run");
        set_exec_count(0);
        let mut inputs = StreamInputs::from_multiinput(input);
        unsafe {  
            *GLOB_INPUT.get() = (&mut inputs) as *mut StreamInputs;
        }

        let mut in_simulator = state.emulator_mut();
        let mut in_qemu = in_simulator.qemu();
        let mut in_cpu = in_qemu.first_cpu().unwrap();
        let exit_reason;
        let exit_code;
        unsafe {
            exit_reason = in_qemu.run();
        }
        if let Ok(qemu_exit_reason) = exit_reason
        {
            if let QemuExitReason::SyncExit = qemu_exit_reason
            {
                let cmd : GuestReg = cpu.read_reg(Regs::Rax).unwrap();
                let arg1 : GuestReg = cpu.read_reg(Regs::Rdi).unwrap();
                debug!("qemu_run_to_end sync exit {:#x} {:#x}",cmd,arg1);
                if cmd == 6 {
                    let dev_filter = DeviceSnapshotFilter::DenyList(get_snapshot_dev_filter_list());
                    unsafe {
                        *SMM_FUZZ_SNAPSHOT.get() = Some(in_simulator.create_fast_snapshot_filter(true,&dev_filter));
                    }
                    exit_code = ExitKind::Ok;
                }
                else {
                    exit_code = ExitKind::Crash;
                }
                
            }
            else if let QemuExitReason::End(_) = qemu_exit_reason
            {
                exit_code = ExitKind::Crash;
            }
            else if let QemuExitReason::Breakpoint(_) = qemu_exit_reason
            {
                debug!("qemu_run_to_end qemu breakpoint");
                exit_code = ExitKind::Crash;
            }
            else
            {
                debug!("qemu_run_to_end qemu exit error");
                exit_elegantly();
                exit_code = ExitKind::Ok;
            }
        }
        else
        {
            debug!("qemu_run_to_end get qemu exit reason error");
            exit_elegantly();
            exit_code = ExitKind::Ok;
        }
        unsafe {
            in_simulator.restore_fast_snapshot(snap);
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

    let mon = SimpleMonitor::new(|s| info!("{s}"));
    let mut mgr = SimpleEventManager::new(mon);
    let scheduler = PowerQueueScheduler::new(&mut state, &mut edges_observer, PowerSchedule::FAST);
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);


    let mut executor = StatefulQemuExecutor::new(
        &mut emulator,
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
                info!("Failed to load initial corpus at {:?}", &corpus_dirs);
                process::exit(0);
            });
            info!("We imported {} inputs from disk.", state.corpus().count());
    }
    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    while true {
        fuzzer
            .fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr)
            .unwrap();
        unsafe {
            if let Some(s) = *SMM_FUZZ_SNAPSHOT.get() {
                break;
            }
        }
    }
    return unsafe { (*SMM_FUZZ_SNAPSHOT.get()).unwrap() };

}