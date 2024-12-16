
mod qemu_args;
mod sparse_memory;
mod cpu_hooks;
mod exit_qemu;
mod init_fuzz_phase;
mod smm_fuzz_phase;
mod stream_input;
mod common_hooks;
mod cmd;
mod qemu_control;
mod fuzzer_snapshot;
mod smm_fuzz_qemu_cmds;
use core::{ptr::addr_of_mut, time::Duration};
use std::cell::UnsafeCell;
use std::process::exit;
use std::str::FromStr;
use std::{path::PathBuf, process};
use log::*;
use clap::Parser;
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
use std::path::Path;
use fern::Dispatch;
use libafl_qemu::FastSnapshotPtr;
use crate::stream_input::*;
use crate::qemu_args::*;
use crate::common_hooks::*;
use crate::cmd::*;
use crate::exit_qemu::*;
use crate::fuzzer_snapshot::*;
use crate::smm_fuzz_phase::{smm_phase_fuzz, smm_phase_run};
use init_fuzz_phase::{init_phase_fuzz, init_phase_run};
use std::io::{self, Write};
use std::thread;
use crate::smm_fuzz_qemu_cmds::*;


#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    ovmf_code: String,

    #[arg(short, long)]
    ovmf_var: String,

    #[arg(short, long)]
    proj: String,

    #[arg(short, long)]
    cmd: String,

    #[arg(short, long)]
    smi_input: Option<String>,
}


fn main() {
    env_logger::init();
    let args = Args::parse();

    let project_path = Path::new(args.proj.as_str());
    if !project_path.exists() {
        fs::create_dir_all(project_path.clone()).unwrap();
    }

    let seed_path = project_path.join("seed");
    if !seed_path.exists() {
        fs::create_dir_all(seed_path.clone()).unwrap();
    }

    let corpus_path = project_path.join("corpus");
    if !corpus_path.exists() {
        fs::create_dir_all(corpus_path.clone()).unwrap();
    }

    let crash_path = project_path.join("crash");
    if !crash_path.exists() {
        fs::create_dir_all(crash_path.clone()).unwrap();
    }

    
    if args.cmd == "fuzz" {
        fuzz((args.ovmf_code, args.ovmf_var), &seed_path, &corpus_path, &crash_path);
    } else if args.cmd == "run_one" {
        let run_mode = RunMode::RunTestcase(PathBuf::from_str(args.smi_input.unwrap().as_str()).unwrap());
        run_smi((args.ovmf_code, args.ovmf_var), &corpus_path,run_mode);
    } else if args.cmd == "run_corpus" {
        let run_mode = RunMode::RunTestcase(PathBuf::from_str(args.smi_input.unwrap().as_str()).unwrap());
        run_smi((args.ovmf_code, args.ovmf_var), &corpus_path,run_mode);
    }
}

fn setup_init_phase_dirs(module_index : usize, seed_dir : &PathBuf, corpus_dir : &PathBuf,  crash_dir : &PathBuf) -> ([PathBuf;1], PathBuf, PathBuf) {
    let seed_dirs = [seed_dir.join(PathBuf::from(format!("init_phase_seed_{}/", module_index)))];
    let corpus_dir = corpus_dir.join(PathBuf::from(format!("init_phase_corpus_{}/", module_index)));
    let objective_dir = crash_dir.join(PathBuf::from(format!("init_phase_crash_{}/", module_index)));
    
    if fs::metadata(seed_dirs[0].clone()).is_ok() {
        fs::remove_dir_all(seed_dirs[0].clone()).unwrap();
    }
    if fs::metadata(corpus_dir.clone()).is_ok() {
        fs::remove_dir_all(corpus_dir.clone()).unwrap();
    }
    if fs::metadata(objective_dir.clone()).is_ok() {
        fs::remove_dir_all(objective_dir.clone()).unwrap();
    }
    
    fs::create_dir_all(seed_dirs[0].clone()).unwrap();
    fs::create_dir_all(corpus_dir.clone()).unwrap();
    fs::create_dir_all(objective_dir.clone()).unwrap();
    

    (seed_dirs, corpus_dir, objective_dir)
}
fn get_init_phase_corpus_dir(module_index : usize, corpus_dir : &PathBuf) -> PathBuf {
    corpus_dir.join(PathBuf::from(format!("init_phase_corpus_{}/", module_index)))
}


fn setup_smi_fuzz_phase_dirs( seed_dir : &PathBuf, corpus_dir : &PathBuf,  crash_dir : &PathBuf) -> ([PathBuf;1], PathBuf, PathBuf) {
    let seed_dirs = [seed_dir.join(PathBuf::from(format!("smi_phase_seed/")))];
    let corpus_dir = corpus_dir.join(PathBuf::from(format!("smi_phase_corpus/")));
    let objective_dir = crash_dir.join(PathBuf::from(format!("smi_phase_crash/")));
    
    if fs::metadata(seed_dirs[0].clone()).is_ok() {
        fs::remove_dir_all(seed_dirs[0].clone()).unwrap();
    }
    if fs::metadata(corpus_dir.clone()).is_ok() {
        fs::remove_dir_all(corpus_dir.clone()).unwrap();
    }
    if fs::metadata(objective_dir.clone()).is_ok() {
        fs::remove_dir_all(objective_dir.clone()).unwrap();
    }
    
    fs::create_dir_all(seed_dirs[0].clone()).unwrap();
    fs::create_dir_all(corpus_dir.clone()).unwrap();
    fs::create_dir_all(objective_dir.clone()).unwrap();
    

    (seed_dirs, corpus_dir, objective_dir)
}
fn get_smi_fuzz_phase_dirs(corpus_dir : &PathBuf) -> PathBuf {
    corpus_dir.join(PathBuf::from(format!("smi_phase_corpus/")))
}

fn fuzz(ovmf_file_path : (String, String), seed_path : &PathBuf, corpus_path : &PathBuf, crash_path : &PathBuf) {
    let args: Vec<String> = gen_ovmf_qemu_args(&ovmf_file_path.0, &ovmf_file_path.1);
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

    unsafe {
        let (qemu_exit_reason, pc, cmd, sync_exit_reason, arg1, arg2) = qemu_run_once(qemu, &FuzzerSnapshot::new_empty(),10000000,false, false);
        if let Ok(qemu_exit_reason) = qemu_exit_reason {
            if let QemuExitReason::SyncExit = qemu_exit_reason  {
                if cmd == LIBAFL_QEMU_COMMAND_END {  // sync exit
                    if sync_exit_reason == LIBAFL_QEMU_END_SMM_INIT_START {
                        set_current_module(arg1, arg2);
                        snapshot = SnapshotKind::StartOfSmmInitSnap(FuzzerSnapshot::from_qemu(qemu));
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
    // let mut devwrite_id : PreDeviceregWriteHookId = emulator.modules_mut().devwrite(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : *mut bool| {
    //     pre_io_write_init_fuzz_phase(base, offset,size , data , handled, modules.qemu().first_cpu().unwrap());
    // })));
    let mut memrw_id = emulator.modules_mut().memrw(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, pc : GuestAddr, addr : GuestAddr, size : u64, out_addr : *mut GuestAddr, rw : u32 , value : u128| {
        let fuzz_input = unsafe {&mut (*GLOB_INPUT) };
        pre_memrw_init_fuzz_phase(pc, addr, size, out_addr,rw, value, fuzz_input, modules.qemu().first_cpu().unwrap());
    })));
    

    let mut module_index = 0;
    loop {
        // fuzz module init function one by one
        match snapshot {
            SnapshotKind::None => {   // we fail, start from the very begining.
                error!("got None"); 
                exit_elegantly();
            },
            SnapshotKind::StartOfUefiSnap(_) => { 
                error!("got StartOfUefi"); 
                exit_elegantly();
            },
            SnapshotKind::StartOfSmmInitSnap(snap) => {
                let (seed_dirs, corpus_dir, crash_dir) = setup_init_phase_dirs(module_index, seed_path, corpus_path, crash_path);
                snapshot = init_phase_fuzz(seed_dirs, corpus_dir, crash_dir, &mut emulator); 
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
    // devwrite_id.remove(true);
    memrw_id.remove(true);


    let mut devread_id : PostDeviceregReadHookId = emulator.modules_mut().devread(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : u32| {
        let fuzz_input = unsafe {&mut (*GLOB_INPUT) };
        post_io_read_smm_fuzz_phase(base , offset ,size , data , handled,fuzz_input ,modules.qemu().first_cpu().unwrap());
    })));
    // let mut devwrite_id : PreDeviceregWriteHookId = emulator.modules_mut().devwrite(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : *mut bool| {
    //     pre_io_write_smm_fuzz_phase(base, offset,size , data , handled, modules.qemu().first_cpu().unwrap());
    // })));
    let mut memrw_id = emulator.modules_mut().memrw(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, pc : GuestAddr, addr : GuestAddr, size : u64, out_addr : *mut GuestAddr, rw : u32 , value : u128| {
        let fuzz_input = unsafe {&mut (*GLOB_INPUT) };
        pre_memrw_smm_fuzz_phase(pc, addr, size, out_addr,rw, value, fuzz_input, modules.qemu().first_cpu().unwrap());
    })));
    let rdmsr_id = emulator.modules_mut().rdmsr(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, in_ecx: u32, out_eax: *mut u32, out_edx: *mut u32| {
        let fuzz_input = unsafe {&mut (*GLOB_INPUT) };
        rdmsr_smm_fuzz_phase(in_ecx, out_eax, out_edx, fuzz_input);
    })));

    let (seed_dirs, corpus_dir, crash_dir) = setup_smi_fuzz_phase_dirs(seed_path, corpus_path, crash_path);
    smm_phase_fuzz(seed_dirs, corpus_dir, crash_dir, &mut emulator);
}


fn run_smi(ovmf_file_path : (String, String), corpus_path : &PathBuf, run_mode : RunMode) {

    let args: Vec<String> = gen_ovmf_qemu_args(&ovmf_file_path.0, &ovmf_file_path.1);
    let env: Vec<(String, String)> = env::vars().collect();
    let qemu: Qemu = Qemu::init(args.as_slice(),env.as_slice()).unwrap();
    let mut emulator  = Emulator::new_with_qemu(qemu,
        tuple_list!(),
        NopEmulatorExitHandler,
        NopCommandManager)
        .unwrap();
    let cpu = qemu.first_cpu().unwrap();
    
    let backdoor_id = emulator.modules_mut().backdoor(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, addr : GuestAddr| {
        let fuzz_input = unsafe {&mut (*GLOB_INPUT) };
        backdoor_common(fuzz_input, modules.qemu().first_cpu().unwrap());
    })));

    let mut snapshot = SnapshotKind::None;
    unsafe {
        let (qemu_exit_reason, pc, cmd, sync_exit_reason, arg1, arg2) = qemu_run_once(qemu, &FuzzerSnapshot::new_empty(),10000000,false, false);
        if let Ok(qemu_exit_reason) = qemu_exit_reason {
            if let QemuExitReason::SyncExit = qemu_exit_reason  {
                if cmd == LIBAFL_QEMU_COMMAND_END {  // sync exit
                    if sync_exit_reason == LIBAFL_QEMU_END_SMM_INIT_START {
                        set_current_module(arg1, arg2);
                        snapshot = SnapshotKind::StartOfSmmInitSnap(FuzzerSnapshot::from_qemu(qemu));
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
        bbl_debug(modules.qemu().first_cpu().unwrap()); 
    })));
    let mut devread_id : PostDeviceregReadHookId = emulator.modules_mut().devread(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : u32| {
        let fuzz_input = unsafe {&mut (*GLOB_INPUT) };
        post_io_read_init_fuzz_phase(base , offset ,size , data , handled,fuzz_input ,modules.qemu().first_cpu().unwrap());
    })));
    // let mut devwrite_id : PreDeviceregWriteHookId = emulator.modules_mut().devwrite(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : *mut bool| {
    //     pre_io_write_init_fuzz_phase(base, offset,size , data , handled, modules.qemu().first_cpu().unwrap());
    // })));
    let mut memrw_id = emulator.modules_mut().memrw(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, pc : GuestAddr, addr : GuestAddr, size : u64, out_addr : *mut GuestAddr, rw : u32 , value : u128| {
        let fuzz_input = unsafe {&mut (*GLOB_INPUT) };
        pre_memrw_init_fuzz_phase(pc, addr, size, out_addr,rw, value, fuzz_input, modules.qemu().first_cpu().unwrap());
    })));
    

    let mut module_index = 0;
    loop {
        // fuzz module init function one by one
        match snapshot {
            SnapshotKind::None => {   // we fail, start from the very begining.
                error!("got None"); 
                exit_elegantly();
            },
            SnapshotKind::StartOfUefiSnap(_) => { 
                error!("got StartOfUefi"); 
                exit_elegantly();
            },
            SnapshotKind::StartOfSmmInitSnap(snap) => {
                let corpus_dir = get_init_phase_corpus_dir(module_index, corpus_path);
                snapshot = init_phase_run(corpus_dir, &mut emulator); 
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
    // devwrite_id.remove(true);
    memrw_id.remove(true);


    let mut devread_id : PostDeviceregReadHookId = emulator.modules_mut().devread(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : u32| {
        let fuzz_input = unsafe {&mut (*GLOB_INPUT) };
        post_io_read_smm_fuzz_phase(base , offset ,size , data , handled,fuzz_input ,modules.qemu().first_cpu().unwrap());
    })));
    // let mut devwrite_id : PreDeviceregWriteHookId = emulator.modules_mut().devwrite(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : *mut bool| {
    //     pre_io_write_smm_fuzz_phase(base, offset,size , data , handled, modules.qemu().first_cpu().unwrap());
    // })));
    let mut memrw_id = emulator.modules_mut().memrw(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, pc : GuestAddr, addr : GuestAddr, size : u64, out_addr : *mut GuestAddr, rw : u32 , value : u128| {
        let fuzz_input = unsafe {&mut (*GLOB_INPUT) };
        pre_memrw_smm_fuzz_phase(pc, addr, size, out_addr,rw, value, fuzz_input, modules.qemu().first_cpu().unwrap());
    })));
    let rdmsr_id = emulator.modules_mut().rdmsr(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, in_ecx: u32, out_eax: *mut u32, out_edx: *mut u32| {
        let fuzz_input = unsafe {&mut (*GLOB_INPUT) };
        rdmsr_smm_fuzz_phase(in_ecx, out_eax, out_edx, fuzz_input);
    })));

    
    smm_phase_run(run_mode, &mut emulator);
}