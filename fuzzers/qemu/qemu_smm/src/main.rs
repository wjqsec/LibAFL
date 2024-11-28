
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
mod smm_fuzz_qemu_cmds;
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
        edges_map_mut_ptr, EdgeCoverageModule,EdgeCoverageClassicModule, EDGES_MAP_SIZE_IN_USE, MAX_EDGES_FOUND,
    }, Emulator, NopEmulatorExitHandler, PostDeviceregReadHookId, PreDeviceregWriteHookId, Qemu, QemuExitReason, Regs
};
use libafl_qemu_sys::GuestAddr;
use libafl_qemu::{Hook, HookId};
use libafl_qemu::modules::edges::gen_hashed_block_ids;
use libafl_qemu::GuestReg;
use libafl_qemu::qemu::BlockHookId;
use libafl_qemu::CPU;
use libafl_qemu::DeviceSnapshotFilter;
use libafl_qemu::modules::CmpLogModule;
use std::env;
use libafl_qemu::FastSnapshotPtr;
use crate::stream_input::*;
use crate::qemu_args::*;
use crate::common_hooks::*;
use crate::config::*;
use crate::exit_qemu::*;
use crate::fuzzer_snapshot::*;
use crate::smm_fuzz_phase::smm_phase_fuzz;
use init_fuzz_phase::init_phase_fuzz;
use std::io::{self, Write};
use std::thread;
use crate::smm_fuzz_qemu_cmds::*;




#[allow(clippy::too_many_lines)]
fn main() {
    env_logger::init();

    fs::create_dir_all(INIT_PHASE_CORPUS_DIR).unwrap();
    fs::create_dir_all(INIT_PHASE_SOLUTION_DIR).unwrap();

    let args: Vec<String> = gen_ovmf_qemu_args();
    let env: Vec<(String, String)> = env::vars().collect();
    let qemu: Qemu = Qemu::init(args.as_slice(),env.as_slice()).unwrap();
    let mut emulator  = Emulator::new_with_qemu(qemu,
        tuple_list!(EdgeCoverageModule::default(), CmpLogModule::default()),
        NopEmulatorExitHandler,
        NopCommandManager)
        .unwrap();
    let cpu = qemu.first_cpu().unwrap();
    
    let backdoor_id = emulator.modules_mut().backdoor(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, addr : GuestAddr| {
        let fuzz_input = unsafe {&mut (*GLOB_INPUT) };
        backdoor_common(fuzz_input, modules.qemu().first_cpu().unwrap());
    })));

    let mut snapshot = SnapshotKind::None;
    let mut first_snapshot_backup = FuzzerSnapshot::new_empty();
    unsafe {
        let (qemu_exit_reason, pc, cmd, sync_exit_reason, arg1, arg2) = qemu_run_once(qemu, &FuzzerSnapshot::new_empty(),10000000,false, false);
        if let Ok(qemu_exit_reason) = qemu_exit_reason {
            if let QemuExitReason::SyncExit = qemu_exit_reason  {
                if cmd == LIBAFL_QEMU_COMMAND_END {  // sync exit
                    if sync_exit_reason == LIBAFL_QEMU_END_SMM_INIT_START {
                        set_current_module(arg1, arg2);
                        snapshot = SnapshotKind::StartOfSmmInitSnap(FuzzerSnapshot::from_qemu(qemu));
                        first_snapshot_backup = FuzzerSnapshot::from_qemu_untrack(qemu);
                    }
                }
            }
        }
    }
    if let SnapshotKind::None = snapshot {
        error!("first breakpoint hit strange place");
        exit_elegantly();
    }
    info!("first breakpoint hit");

    
    let mut block_id = emulator.modules_mut().blocks(Hook::Function(gen_hashed_block_ids::<_, _>), Hook::Empty, 
    Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, id: u64| {
        bbl_common(modules.qemu().first_cpu().unwrap()); 
    })));
    let mut devread_id : PostDeviceregReadHookId = emulator.modules_mut().devread(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : u32| {
        let fuzz_input = unsafe {&mut (*GLOB_INPUT) };
        post_io_read_init_fuzz_phase(base , offset ,size , data , handled,fuzz_input ,modules.qemu().first_cpu().unwrap());
    })));
    let mut devwrite_id : PreDeviceregWriteHookId = emulator.modules_mut().devwrite(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : *mut bool| {
        pre_io_write_init_fuzz_phase(base, offset,size , data , handled, modules.qemu().first_cpu().unwrap());
    })));
    let mut memrw_id = emulator.modules_mut().memrw(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, pc : GuestAddr, addr : GuestAddr, size : u64, out_addr : *mut GuestAddr, rw : u32 , value : u128| {
        let fuzz_input = unsafe {&mut (*GLOB_INPUT) };
        pre_memrw_init_fuzz_phase(pc, addr, size, out_addr,rw, value, fuzz_input, modules.qemu().first_cpu().unwrap());
    })));
    

    let mut module_index = 0;
    loop {
        // fuzz module init function one by one
        match snapshot {
            SnapshotKind::None => {   // we fail, start from the very begining.
                module_index = 0;
                first_snapshot_backup.restore_fuzz_snapshot(qemu, true);
                snapshot = SnapshotKind::StartOfSmmInitSnap(FuzzerSnapshot::from_qemu(qemu));
                error!("***************** restart *****************");
            },
            SnapshotKind::StartOfUefiSnap(_) => { 
                error!("got StartOfUefi"); 
                exit_elegantly();
            },
            SnapshotKind::StartOfSmmInitSnap(snap) => {
                snapshot = init_phase_fuzz(module_index, &mut emulator); 
                snap.delete(qemu);
                module_index += 1;
                info!("passed one module");
            },
            SnapshotKind::EndOfSmmInitSnap(_) => { 
                error!("got EndOfSmmInitSnap"); 
                exit_elegantly();
            },
            SnapshotKind::StartOfSmmModuleSnap(snap) => { 
                info!("passed all modules");
                break;
            },
            SnapshotKind::StartOfSmmFuzzSnap(_) => { 
                error!("got StartOfSmmFuzzSnap"); 
                exit_elegantly();
            },
        };
    }

    devread_id.remove(true);
    devwrite_id.remove(true);
    memrw_id.remove(true);


    let mut devread_id : PostDeviceregReadHookId = emulator.modules_mut().devread(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : u32| {
        let fuzz_input = unsafe {&mut (*GLOB_INPUT) };
        post_io_read_smm_fuzz_phase(base , offset ,size , data , handled,fuzz_input ,modules.qemu().first_cpu().unwrap());
    })));
    let mut devwrite_id : PreDeviceregWriteHookId = emulator.modules_mut().devwrite(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : *mut bool| {
        pre_io_write_smm_fuzz_phase(base, offset,size , data , handled, modules.qemu().first_cpu().unwrap());
    })));
    let mut memrw_id = emulator.modules_mut().memrw(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, pc : GuestAddr, addr : GuestAddr, size : u64, out_addr : *mut GuestAddr, rw : u32 , value : u128| {
        let fuzz_input = unsafe {&mut (*GLOB_INPUT) };
        pre_memrw_smm_fuzz_phase(pc, addr, size, out_addr,rw, value, fuzz_input, modules.qemu().first_cpu().unwrap());
    })));
    let rdmsr_id = emulator.modules_mut().rdmsr(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, in_ecx: u32, out_eax: *mut u32, out_edx: *mut u32| {
        let fuzz_input = unsafe {&mut (*GLOB_INPUT) };
        rdmsr_smm_fuzz_phase(in_ecx, out_eax, out_edx, fuzz_input);
    })));
    smm_phase_fuzz(&mut emulator);
}
