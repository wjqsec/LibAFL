
mod qemu_args;
mod sparse_memory;
mod cpu_hooks;
mod exit_qemu;
mod init_fuzz_phase;
mod smm_fuzz_phase;
mod stream_input;
mod common_hooks;
mod config;
mod qemu_control;
mod fuzzer_snapshot;
use core::{ptr::addr_of_mut, time::Duration};
use std::cell::UnsafeCell;
use std::process::exit;
use std::{path::PathBuf, process};
use log::*;
use qemu_control::qemu_run_once;
use std::fs;
use libafl::{
    corpus::Corpus, executors::ExitKind, feedback_or, feedback_or_fast, feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback}, fuzzer::{Fuzzer, StdFuzzer}, inputs::{BytesInput, Input}, mutators::scheduled::{havoc_mutations, StdScheduledMutator}, observers::{stream::StreamObserver, CanTrack, HitcountsMapObserver, TimeObserver, VariableMapObserver}, prelude::{powersched::PowerSchedule, CachedOnDiskCorpus, PowerQueueScheduler, SimpleEventManager, SimpleMonitor}, stages::StdMutationalStage, state::{HasCorpus, StdState}
};
use libafl_bolts::tuples::MatchNameRef;
use libafl::feedbacks::stream::StreamFeedback;
use libafl::inputs::multi::MultipartInput;
use std::sync::{Arc, Mutex};
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
use libafl_qemu::Hook;
use libafl_qemu::modules::edges::gen_hashed_block_ids;
use libafl_qemu::GuestReg;
use libafl_qemu::qemu::BlockHookId;
use libafl_qemu::CPU;
use libafl_qemu::DeviceSnapshotFilter;
use std::env;
use libafl_qemu::FastSnapshotPtr;
use crate::stream_input::*;
use crate::qemu_args::*;
use crate::common_hooks::*;
use crate::config::*;
use crate::exit_qemu::*;
use crate::fuzzer_snapshot::*;
use init_fuzz_phase::*;
use std::io::{self, Write};
use std::thread;





#[allow(clippy::too_many_lines)]
fn main() {
    env_logger::init();

    fs::create_dir_all(INIT_PHASE_CORPUS_DIR).unwrap();
    fs::create_dir_all(INIT_PHASE_SOLUTION_DIR).unwrap();

    let args: Vec<String> = gen_ovmf_qemu_args();
    let env: Vec<(String, String)> = env::vars().collect();
    let qemu: Qemu = Qemu::init(args.as_slice(),env.as_slice()).unwrap();
    let mut emulator  = Emulator::new_with_qemu(qemu,
        tuple_list!(EdgeCoverageModule::default()),
        NopEmulatorExitHandler,
        NopCommandManager)
        .unwrap();

    
    let backdoor_id = emulator.modules_mut().backdoor(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, addr : GuestAddr| {
        backdoor_common(modules.qemu().first_cpu().unwrap());
    })));

    unsafe {
        let first_exit = qemu_run_once(qemu, &FuzzerSnapshot::new_empty());
        let cmd : GuestReg = qemu.first_cpu().unwrap().read_reg(Regs::Rax).unwrap();
        let arg1 : GuestReg = qemu.first_cpu().unwrap().read_reg(Regs::Rdi).unwrap();
        let pc : GuestReg = qemu.first_cpu().unwrap().read_reg(Regs::Rip).unwrap();
        info!("first exit <{:?}> {cmd} {arg1} {:#x}",first_exit,pc);
    }


    
    let block_id = emulator.modules_mut().blocks(Hook::Function(gen_hashed_block_ids::<_, _>), Hook::Empty, 
    Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, id: u64| {
        bbl_common(modules.qemu().first_cpu().unwrap()); 
    })));
    let devread_id : PostDeviceregReadHookId = emulator.modules_mut().devread(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : u32| {
        let fuzz_input = unsafe {&mut (*GLOB_INPUT) };
        post_io_read_init_fuzz_phase(base , offset ,size , data , handled,fuzz_input ,modules.qemu().first_cpu().unwrap());
    })));
    let devwrite_id : PreDeviceregWriteHookId = emulator.modules_mut().devwrite(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : *mut bool| {
        pre_io_write_init_fuzz_phase(base, offset,size , data , handled, modules.qemu().first_cpu().unwrap());
    })));
    let memrw_id = emulator.modules_mut().memrw(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, pc : GuestAddr, addr : GuestAddr, size : u64, out_addr : *mut GuestAddr, rw : u32 , value : u128| {
        let fuzz_input = unsafe {&mut (*GLOB_INPUT) };
        pre_memrw_init_fuzz_phase(pc, addr, size, out_addr,rw, value, fuzz_input, modules.qemu().first_cpu().unwrap());
    })));
    // fuzz module init function one by one

    // for test
    // unsafe {
    //     let sss = FuzzerSnapshot::from_qemu(qemu);
    //     sss.restore_fuzz_snapshot(qemu);
    //     qemu.run();
    //     sss.restore_fuzz_snapshot(qemu);
    // }
    // exit_elegantly();

    let mut snapshot = SnapshotKind::StartOfSmmInitSnap(FuzzerSnapshot::from_qemu(qemu));
    loop {
        snapshot = init_phase_fuzz::<NopCommandManager, NopEmulatorExitHandler, (EdgeCoverageModule, ()), StdState<MultipartInput<BytesInput>, CachedOnDiskCorpus<MultipartInput<BytesInput>>, libafl_bolts::prelude::RomuDuoJrRand, CachedOnDiskCorpus<MultipartInput<BytesInput>>>>(&mut emulator ,snapshot);
        match snapshot {
            SnapshotKind::None => { 
                error!("got None"); 
                exit_elegantly();
            },
            SnapshotKind::StartOfUefiSnap(_) => { 
                error!("got StartOfUefi"); 
                exit_elegantly();
            },
            SnapshotKind::StartOfSmmInitSnap(_) => { 
                info!("passed one module");
            },
            SnapshotKind::EndOfSmmInitSnap(_) => { 
                error!("got EndOfSmmInitSnap"); 
                exit_elegantly();
            },
            SnapshotKind::StartOfSmmFuzzSnap(_) => { 
                break; 
            },
        };
    }
    info!("finish init phase fuzzing!");
    exit_elegantly();
    
   
    // let cpuid_id = emulator.modules_mut().cpuid(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, in_eax: u32, out_eax: *mut u32,out_ebx: *mut u32, out_ecx: *mut u32, out_edx: *mut u32| {
    //     let pc : GuestReg = current_cpu.read_reg(Regs::Pc).unwrap();
    //     cpuid_common(pc, in_eax,out_eax,out_ebx,out_ecx,out_edx);
    // })));
    // let rdmsr_id = emulator.modules_mut().rdmsr(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, in_ecx: u32, out_eax: *mut u32, out_edx: *mut u32| {
    //     let pc : GuestReg = current_cpu.read_reg(Regs::Pc).unwrap();
    //     rdmsr_common(pc, in_ecx, out_eax, out_edx);
    // })));
    // let wrmsr_id = emulator.modules_mut().wrmsr(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, in_ecx: u32, in_eax: *mut u32, in_edx: *mut u32| {
    //     let pc : GuestReg = current_cpu.read_reg(Regs::Pc).unwrap();
    //     wrmsr_common(pc, in_ecx, in_eax, in_edx);
    // })));
 

    // let mut cmplogob = CmpLogObserver::new("cmplogob", true);
    
    // let mut aflcmplog_executor = StatefulQemuExecutor::new(
    //     &mut emulator,
    //     &mut harness,
    //     tuple_list!(cmplogob),
    //     &mut fuzzer,
    //     &mut state,
    //     &mut mgr,
    //     timeout,
    // )
    // .expect("Failed to create QemuExecutor");

    // let colorization_stage = ColorizationStage::new(&mut edges_observer);

    // let aflpp_tracing_stage = TracingStage::new(
    //     aflcmplog_executor
    // );

    // let rq_stage = MultiMutationalStage::new(AFLppRedQueen::with_cmplog_options(true, true));

    // let cb = |_fuzzer: &mut _,
    //               _executor: &mut _,
    //               state: &mut StdState<_, CachedOnDiskCorpus<_>, _, _>,
    //               _event_manager: &mut _|
    //      -> Result<bool, Error> {
    //         let testcase = state.current_testcase()?;
    //         let res = testcase.scheduled_count() == 1; // let's try on the 2nd trial

    //         Ok(res)
    //     };

    // let cmplog = IfStage::new(cb, tuple_list!(colorization_stage, aflpp_tracing_stage, rq_stage));
    
}
