
mod qemu_args;
mod sparse_memory;
mod exit_qemu;
mod init_fuzz_phase;
mod smm_fuzz_phase;
mod stream_input;
mod common_hooks;
mod smi_info;
mod coverage;
mod qemu_control;
mod fuzzer_snapshot;
mod smm_fuzz_qemu_cmds;
use core::{ptr::addr_of_mut, time::Duration};
use std::cell::UnsafeCell;
use std::process::exit;
use std::str::FromStr;
use std::{path::PathBuf, process};
use log::*;
use std::fs::File;
use std::io::{self, Write};
use clap::{Parser, ValueEnum, ArgGroup, Subcommand};
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
use crate::smi_info::*;
use crate::coverage::*;
use crate::exit_qemu::*;
use crate::fuzzer_snapshot::*;
use crate::smm_fuzz_phase::{smm_phase_fuzz, smm_phase_run};
use init_fuzz_phase::{init_phase_fuzz, init_phase_run, set_init_fuzz_timeout_time};
use std::thread;
use crate::smm_fuzz_qemu_cmds::*;

fn parse_duration(src: &str) -> Result<Duration, String> {
    let units = &src[src.len().saturating_sub(1)..];
    let value = &src[..src.len().saturating_sub(1)];
    
    let multiplier = match units {
        "s" | "S" => 1,
        "m" | "M" => 60,
        "h" | "H" => 3600,
        "d" | "D" => 86400,
        _ => return Err("Invalid time unit, use 's', 'm', 'h', or 'd'".to_string()),
    };

    let parsed_value = value.parse::<u64>()
        .map_err(|_| format!("Invalid numeric value: {}", value))?;
    
    Ok(Duration::from_secs(parsed_value * multiplier))
}
#[derive(Subcommand, Clone, Debug, PartialEq)]
enum SmmCommand {
    Fuzz {
        #[arg(short, long)]
        ovmf_code: Option<String>,
    
        #[arg(short, long)]
        ovmf_var: Option<String>,

        #[arg(short, long, action = clap::ArgAction::SetTrue)]
        use_snapshot: bool,

        #[arg(short, long, action = clap::ArgAction::SetTrue)]
        save_tmp_snapshot: bool,

        #[arg(long, value_parser = parse_duration)]
        fuzz_time: Option<Duration>,

        #[arg(long, value_parser = parse_duration)]
        init_phase_timeout_time: Option<Duration>,
    },
    Replay {
        #[arg(short, long)]
        inputs: String,
    },
    Coverage {
        #[arg(short, long)]
        cov_module: Option<String>,

        #[arg(short, long)]
        output: Option<String>,

        #[arg(short, long, action = clap::ArgAction::SetTrue)]
        include_init_phase: bool,
    },
    Report {

    },
}


#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    cmd: SmmCommand,

    #[arg(short, long)]
    proj: String,

    #[arg(short, long)]
    tag: Option<String>,
}


fn main() {
    env_logger::init();

    let args = Args::parse();

    let project_path = Path::new(args.proj.as_str());
    if !project_path.exists() {
        fs::create_dir_all(project_path.clone()).unwrap();
    }
    let ovmf_code_copy = project_path.join("OVMF_CODE.fd");
    let ovmf_var_copy = project_path.join("OVMF_VARS.fd");
    let mut fuzz_tag = String::from_str("test_fuzz").unwrap();
    if let Some(tag) = args.tag {
        fuzz_tag = tag;
    }
    let seed_path = project_path.join(fuzz_tag.clone()).join("seed");
    let corpus_path = project_path.join(fuzz_tag.clone()).join("corpus");
    let crash_path = project_path.join(fuzz_tag.clone()).join("crash");
    let snapshot_path = project_path.join(fuzz_tag.clone()).join("snapshots");
    let log_file = project_path.join(fuzz_tag.clone()).join("qemu_log.txt");

    set_ovmf_path(&ovmf_code_copy, &ovmf_var_copy, &log_file);

    match args.cmd {
        SmmCommand::Fuzz { ovmf_code, ovmf_var, use_snapshot, save_tmp_snapshot, fuzz_time , init_phase_timeout_time} => {
            if seed_path.exists() {
                fs::remove_dir_all(seed_path.clone()).unwrap();
            }
            if corpus_path.exists() {
                fs::remove_dir_all(corpus_path.clone()).unwrap();
            }
            if crash_path.exists() {
                fs::remove_dir_all(crash_path.clone()).unwrap();
            }
            if snapshot_path.exists() {
                fs::remove_dir_all(snapshot_path.clone()).unwrap();
            }
            fs::create_dir_all(seed_path.clone()).unwrap();
            fs::create_dir_all(corpus_path.clone()).unwrap();
            fs::create_dir_all(crash_path.clone()).unwrap();
            fs::create_dir_all(snapshot_path.clone()).unwrap();

            if let Some(ovmf_code) = ovmf_code {
                fs::copy(ovmf_code, ovmf_code_copy.clone()).unwrap();
            }
            if let Some(ovmf_var) = ovmf_var {
                fs::copy(ovmf_var, ovmf_var_copy.clone()).unwrap();
            }
            if let Some(init_phase_timeout_time) = init_phase_timeout_time {
                set_init_fuzz_timeout_time(init_phase_timeout_time.as_secs());
            }
            if !ovmf_code_copy.exists() || ! ovmf_var_copy.exists() {
                error!("ovmf files not found");
                exit_elegantly(ExitProcessType::Ok);
            }
            fuzz((&seed_path, &corpus_path, &crash_path, &snapshot_path), fuzz_time, use_snapshot, save_tmp_snapshot);
        },
        SmmCommand::Replay { inputs } => {
            if !ovmf_code_copy.exists() || !ovmf_var_copy.exists() {
                error!("ovmf files not found");
                exit_elegantly(ExitProcessType::Ok);
            }
            replay((&seed_path, &corpus_path, &crash_path, &snapshot_path), PathBuf::from_str(inputs.clone().as_str()).unwrap());
        },
        SmmCommand::Coverage {cov_module, output ,include_init_phase} => {
            if let Some(cov_module) = cov_module {
                parse_cov_module_file(&PathBuf::from_str(cov_module.as_str()).unwrap());
            }
            coverage((&seed_path, &corpus_path, &crash_path, &snapshot_path),output, include_init_phase);  
        },
        SmmCommand::Report { } => {
            report((&seed_path, &corpus_path, &crash_path, &snapshot_path));
        }

    }
}

fn get_init_phase_dirs_for_replay(module_index : usize, seed_dir : &PathBuf, corpus_dir : &PathBuf,  crash_dir : &PathBuf, snapshotdir : &PathBuf) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let seed_dirs = seed_dir.join(PathBuf::from(format!("init_phase_seed_{}/", module_index)));
    let corpus_dir = corpus_dir.join(PathBuf::from(format!("init_phase_corpus_{}/", module_index)));
    let objective_dir = crash_dir.join(PathBuf::from(format!("init_phase_crash_{}/", module_index)));
    let snapshot_bin = snapshotdir.join(PathBuf::from(format!("{}.bin", module_index)));
    (seed_dirs, corpus_dir, objective_dir, snapshot_bin)
}

fn setup_init_phase_dirs_for_fuzz(module_index : usize, seed_dir : &PathBuf, corpus_dir : &PathBuf,  crash_dir : &PathBuf, snapshotdir : &PathBuf) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let (seed_dirs, corpus_dir, objective_dir, snapshot_bin) = get_init_phase_dirs_for_replay(module_index, seed_dir, corpus_dir, crash_dir, snapshotdir);
    fs::create_dir_all(seed_dirs.clone()).unwrap();
    fs::create_dir_all(corpus_dir.clone()).unwrap();
    fs::create_dir_all(objective_dir.clone()).unwrap();
    (seed_dirs, corpus_dir, objective_dir, snapshot_bin)
}
fn get_smi_fuzz_phase_dirs_for_replay(seed_dir : &PathBuf, corpus_dir : &PathBuf,  crash_dir : &PathBuf, snapshotdir : &PathBuf) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let seed_dirs = seed_dir.join(PathBuf::from(format!("smi_phase_seed/")));
    let corpus_dir = corpus_dir.join(PathBuf::from(format!("smi_phase_corpus/")));
    let objective_dir = crash_dir.join(PathBuf::from(format!("smi_phase_crash/")));
    let snapshot_bin = corpus_dir.parent().unwrap().join("smi_phase_snapshot.bin");
    (seed_dirs, corpus_dir, objective_dir, snapshot_bin)
}
fn setup_smi_fuzz_phase_dirs_for_fuzz(seed_dir : &PathBuf, corpus_dir : &PathBuf,  crash_dir : &PathBuf, snapshotdir : &PathBuf) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let (seed_dirs, corpus_dir, objective_dir, snapshot_bin) = get_smi_fuzz_phase_dirs_for_replay(seed_dir, corpus_dir, crash_dir, snapshotdir);
    fs::create_dir_all(seed_dirs.clone()).unwrap();
    fs::create_dir_all(corpus_dir.clone()).unwrap();
    fs::create_dir_all(objective_dir.clone()).unwrap();
    (seed_dirs, corpus_dir, objective_dir, snapshot_bin)
}

fn fuzz((seed_path,corpus_path, crash_path, snapshot_path) : (&PathBuf, &PathBuf, &PathBuf, &PathBuf), fuzz_time : Option<Duration>, use_snapshot : bool, save_tmp_snapshot : bool) {
    let args: Vec<String> = gen_ovmf_qemu_args();
    let env: Vec<(String, String)> = env::vars().collect();
    let qemu: Qemu = Qemu::init(args.as_slice(),env.as_slice()).unwrap();
    let mut emulator  = Emulator::new_with_qemu(qemu,
        tuple_list!(EdgeCoverageModule::default(), CmpLogModule::default()),
        NopEmulatorExitHandler,
        NopCommandManager)
        .unwrap();
    setup_ctrlc_handler();
    let cpu = qemu.first_cpu().unwrap();
    let (seed_dirs_smi_phase, corpus_dir_smi_phase, crash_dir_smi_phase, snapshot_bin_smi_phase) = setup_smi_fuzz_phase_dirs_for_fuzz(seed_path, corpus_path, crash_path, snapshot_path);

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
                    if sync_exit_reason == LIBAFL_QEMU_END_SMM_INIT_PREPARE {
                        info!("first breakpoint hit");
                        snapshot = SnapshotKind::StartOfSmmInitSnap(FuzzerSnapshot::new_empty());
                    }
                }
            }
        }
    }
    if let SnapshotKind::None = snapshot {
        error!("first breakpoint hit strange place");
        exit_elegantly(ExitProcessType::Ok);
    }
    

    if use_snapshot {
        if !snapshot_bin_smi_phase.exists() {
            error!("snapshot not found, unable to replay");
            exit_elegantly(ExitProcessType::Ok);
        }
        info!("found snapshot file, start from snapshot!");
        FuzzerSnapshot::restore_from_file(qemu, &snapshot_bin_smi_phase);
        let mut block_id = emulator.modules_mut().blocks(
            Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, pc: u64| -> Option<u64> {
                bbl_translate_smm_fuzz_phase(modules.qemu().first_cpu().unwrap(), pc); 
                Some(pc)
            })),
        Hook::Empty, 
        Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, id: u64| {
            bbl_common(modules.qemu().first_cpu().unwrap()); 
        })));
        let mut devread_id : PostDeviceregReadHookId = emulator.modules_mut().devread(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : u32| {
            let fuzz_input = unsafe {&mut (*GLOB_INPUT) };
            post_io_read_smm_fuzz_phase(base , offset ,size , data , handled,fuzz_input ,modules.qemu().first_cpu().unwrap());
        })));
        let mut devwrite_id : PreDeviceregWriteHookId = emulator.modules_mut().devwrite(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : *mut bool| {
            pre_io_write_smm_fuzz_phase(base, offset,size , data , handled, modules.qemu().first_cpu().unwrap());
        })));
        let rdmsr_id = emulator.modules_mut().rdmsr(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, in_ecx: u32, out_eax: *mut u32, out_edx: *mut u32| {
            let fuzz_input = unsafe {&mut (*GLOB_INPUT) };
            rdmsr_smm_fuzz_phase(in_ecx, out_eax, out_edx, fuzz_input);
        })));
        let wrmsr_id = emulator.modules_mut().wrmsr(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, in_ecx: u32, in_eax: *mut u32, in_edx: *mut u32| {
            wrmsr_common(in_ecx, in_eax, in_edx);
        })));
        let mut memrw_id = emulator.modules_mut().memrw(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, pc : GuestAddr, addr : GuestAddr, size : u64, out_addr : *mut GuestAddr, rw : u32 , value : u128| {
            let fuzz_input = unsafe {&mut (*GLOB_INPUT) };
            pre_memrw_smm_fuzz_phase(pc, addr, size, out_addr,rw, value, fuzz_input, modules.qemu().first_cpu().unwrap());
        })));

        smm_phase_fuzz(seed_dirs_smi_phase, corpus_dir_smi_phase, crash_dir_smi_phase, &mut emulator, fuzz_time);
        exit_elegantly(ExitProcessType::Ok);
        unreachable!();
    }


    let mut block_id = emulator.modules_mut().blocks(
        Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, pc: u64| -> Option<u64> {
            bbl_translate_init_fuzz_phase(modules.qemu().first_cpu().unwrap(), pc); 
            Some(pc)
        })),
        Hook::Empty, 
        Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, id: u64| {
        bbl_common(modules.qemu().first_cpu().unwrap()); 
        }))
    );
    let mut devread_id : PostDeviceregReadHookId = emulator.modules_mut().devread(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : u32| {
        let fuzz_input = unsafe {&mut (*GLOB_INPUT) };
        post_io_read_init_fuzz_phase(base , offset ,size , data , handled,fuzz_input ,modules.qemu().first_cpu().unwrap());
    })));
    let mut devwrite_id : PreDeviceregWriteHookId = emulator.modules_mut().devwrite(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : *mut bool| {
        pre_io_write_init_fuzz_phase(base, offset,size , data , handled, modules.qemu().first_cpu().unwrap());
    })));
    let rdmsr_id = emulator.modules_mut().rdmsr(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, in_ecx: u32, out_eax: *mut u32, out_edx: *mut u32| {
        let fuzz_input = unsafe {&mut (*GLOB_INPUT) };
        rdmsr_init_fuzz_phase(in_ecx, out_eax, out_edx, fuzz_input);
    })));
    let wrmsr_id = emulator.modules_mut().wrmsr(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, in_ecx: u32, in_eax: *mut u32, in_edx: *mut u32| {
        wrmsr_common(in_ecx, in_eax, in_edx);
    })));
    let mut memrw_id = emulator.modules_mut().memrw(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, pc : GuestAddr, addr : GuestAddr, size : u64, out_addr : *mut GuestAddr, rw : u32 , value : u128| {
        let fuzz_input = unsafe {&mut (*GLOB_INPUT) };
        pre_memrw_init_fuzz_phase(pc, addr, size, out_addr,rw, value, fuzz_input, modules.qemu().first_cpu().unwrap());
    })));
    // let cpuid_id = emulator.modules_mut().cpuid(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, in_eax: u32, out_eax: *mut u32,out_ebx: *mut u32, out_ecx: *mut u32, out_edx: *mut u32| {
    //     let fuzz_input = unsafe {&mut (*GLOB_INPUT) };
    //     cpuid_init_fuzz_phase(in_eax, out_eax, out_ebx, out_ecx, out_edx, fuzz_input, modules.qemu().first_cpu().unwrap());
    // })));
    

    let mut module_index = 0;
    loop {
        match snapshot {
            SnapshotKind::None => {
                error!("got None"); 
                exit_elegantly(ExitProcessType::Error);
            },
            SnapshotKind::StartOfUefiSnap(_) => { 
                error!("got StartOfUefi"); 
                exit_elegantly(ExitProcessType::Error);
            },
            SnapshotKind::StartOfSmmInitSnap(_) => {
                let (seed_dirs, corpus_dir, crash_dir, snapshot_bin) = setup_init_phase_dirs_for_fuzz(module_index, seed_path, corpus_path, crash_path, snapshot_path);
                if save_tmp_snapshot {
                    FuzzerSnapshot::save_to_file(qemu, &snapshot_bin);
                }
                snapshot = init_phase_fuzz(seed_dirs, corpus_dir, crash_dir, &mut emulator); 
                module_index += 1;
            },
            SnapshotKind::EndOfSmmInitSnap(_) => { 
                error!("got EndOfSmmInitSnap"); 
                exit_elegantly(ExitProcessType::Error);
            },
            SnapshotKind::StartOfSmmModuleSnap(_) => { 
                break;
            },
            SnapshotKind::StartOfSmmFuzzSnap(_) => { 
                error!("got StartOfSmmFuzzSnap"); 
                exit_elegantly(ExitProcessType::Error);
            },
        };
    }
    
    block_id.remove(true);
    devread_id.remove(true);
    devwrite_id.remove(true);
    rdmsr_id.remove(true);
    wrmsr_id.remove(true);
    memrw_id.remove(true);
    
    let mut block_id = emulator.modules_mut().blocks(
        Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, pc: u64| -> Option<u64> {
            bbl_translate_smm_fuzz_phase(modules.qemu().first_cpu().unwrap(), pc); 
            Some(pc)
        })),
        Hook::Empty, 
        Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, id: u64| {
        bbl_common(modules.qemu().first_cpu().unwrap()); 
        }))
    );
    let mut devread_id : PostDeviceregReadHookId = emulator.modules_mut().devread(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : u32| {
        let fuzz_input = unsafe {&mut (*GLOB_INPUT) };
        post_io_read_smm_fuzz_phase(base , offset ,size , data , handled,fuzz_input ,modules.qemu().first_cpu().unwrap());
    })));
    let mut devwrite_id : PreDeviceregWriteHookId = emulator.modules_mut().devwrite(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : *mut bool| {
        pre_io_write_smm_fuzz_phase(base, offset,size , data , handled, modules.qemu().first_cpu().unwrap());
    })));
    let rdmsr_id = emulator.modules_mut().rdmsr(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, in_ecx: u32, out_eax: *mut u32, out_edx: *mut u32| {
        let fuzz_input = unsafe {&mut (*GLOB_INPUT) };
        rdmsr_smm_fuzz_phase(in_ecx, out_eax, out_edx, fuzz_input);
    })));
    let wrmsr_id = emulator.modules_mut().wrmsr(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, in_ecx: u32, in_eax: *mut u32, in_edx: *mut u32| {
        wrmsr_common(in_ecx, in_eax, in_edx);
    })));
    let mut memrw_id = emulator.modules_mut().memrw(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, pc : GuestAddr, addr : GuestAddr, size : u64, out_addr : *mut GuestAddr, rw : u32 , value : u128| {
        let fuzz_input = unsafe {&mut (*GLOB_INPUT) };
        pre_memrw_smm_fuzz_phase(pc, addr, size, out_addr,rw, value, fuzz_input, modules.qemu().first_cpu().unwrap());
    })));
    
    FuzzerSnapshot::save_to_file(qemu, &snapshot_bin_smi_phase);
    smm_phase_fuzz(seed_dirs_smi_phase.clone(), corpus_dir_smi_phase.clone(), crash_dir_smi_phase.clone(), &mut emulator, fuzz_time);
    exit_elegantly(ExitProcessType::Ok);
}

fn replay((seed_path,corpus_path, crash_path, snapshot_path) : (&PathBuf, &PathBuf, &PathBuf, &PathBuf), run_corpus : PathBuf) {
    let args: Vec<String> = gen_ovmf_qemu_args();
    let env: Vec<(String, String)> = env::vars().collect();
    let qemu: Qemu = Qemu::init(args.as_slice(),env.as_slice()).unwrap();
    let mut emulator  = Emulator::new_with_qemu(qemu,
        tuple_list!(),
        NopEmulatorExitHandler,
        NopCommandManager)
        .unwrap();
    setup_ctrlc_handler();
    let cpu = qemu.first_cpu().unwrap();
    let (seed_dirs_smi_phase, corpus_dir_smi_phase, crash_dir_smi_phase, snapshot_bin_smi_phase) = get_smi_fuzz_phase_dirs_for_replay(seed_path, corpus_path, crash_path, snapshot_path);
    if !snapshot_bin_smi_phase.exists() {
        error!("snapshot not found, unable to replay");
        exit_elegantly(ExitProcessType::Ok);
    }

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
                    if sync_exit_reason == LIBAFL_QEMU_END_SMM_INIT_PREPARE {
                        info!("first breakpoint hit");
                    }
                }
            }
        }
    }
    info!("restore snapshot");
    let mut block_id = emulator.modules_mut().blocks(
        Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, pc: u64| -> Option<u64> {
            bbl_translate_smm_fuzz_phase(modules.qemu().first_cpu().unwrap(), pc); 
            Some(pc)
        })),
        Hook::Empty, 
        Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, id: u64| {
        bbl_debug(modules.qemu().first_cpu().unwrap()); 
    })));
    let mut devread_id : PostDeviceregReadHookId = emulator.modules_mut().devread(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : u32| {
        let fuzz_input = unsafe {&mut (*GLOB_INPUT) };
        post_io_read_smm_fuzz_phase(base , offset ,size , data , handled,fuzz_input ,modules.qemu().first_cpu().unwrap());
    })));
    let mut devwrite_id : PreDeviceregWriteHookId = emulator.modules_mut().devwrite(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : *mut bool| {
        pre_io_write_smm_fuzz_phase(base, offset,size , data , handled, modules.qemu().first_cpu().unwrap());
    })));
    let rdmsr_id = emulator.modules_mut().rdmsr(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, in_ecx: u32, out_eax: *mut u32, out_edx: *mut u32| {
        let fuzz_input = unsafe {&mut (*GLOB_INPUT) };
        rdmsr_smm_fuzz_phase(in_ecx, out_eax, out_edx, fuzz_input);
    })));
    let wrmsr_id = emulator.modules_mut().wrmsr(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, in_ecx: u32, in_eax: *mut u32, in_edx: *mut u32| {
        wrmsr_common(in_ecx, in_eax, in_edx);
    })));
    let mut memrw_id = emulator.modules_mut().memrw(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, pc : GuestAddr, addr : GuestAddr, size : u64, out_addr : *mut GuestAddr, rw : u32 , value : u128| {
        let fuzz_input = unsafe {&mut (*GLOB_INPUT) };
        pre_memrw_smm_fuzz_phase_debug(pc, addr, size, out_addr,rw, value, fuzz_input, modules.qemu().first_cpu().unwrap());
    })));

    FuzzerSnapshot::restore_from_file(qemu, &snapshot_bin_smi_phase);
    smm_phase_run(run_corpus, &mut emulator);
    exit_elegantly(ExitProcessType::Ok);
    
}

fn coverage((seed_path,corpus_path, crash_path, snapshot_path) : (&PathBuf, &PathBuf, &PathBuf, &PathBuf), coverage_log : Option<String>, include_init_phase : bool) {
    let mut coverage = Vec::new();
    let args: Vec<String> = gen_ovmf_qemu_args();
    let env: Vec<(String, String)> = env::vars().collect();
    let qemu: Qemu = Qemu::init(args.as_slice(),env.as_slice()).unwrap();
    let mut emulator  = Emulator::new_with_qemu(qemu,
        tuple_list!(),
        NopEmulatorExitHandler,
        NopCommandManager)
        .unwrap();
    let cpu = qemu.first_cpu().unwrap();
    let (seed_dirs_smi_phase, corpus_dir_smi_phase, crash_dir_smi_phase, snapshot_bin_smi_phase) = get_smi_fuzz_phase_dirs_for_replay(seed_path, corpus_path, crash_path, snapshot_path);
    if !snapshot_bin_smi_phase.exists() {
        error!("snapshot not found, unable to replay");
        exit_elegantly(ExitProcessType::Ok);
    }
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
                    if sync_exit_reason == LIBAFL_QEMU_END_SMM_INIT_PREPARE {
                        info!("first breakpoint hit");
                        snapshot = SnapshotKind::StartOfSmmInitSnap(FuzzerSnapshot::new_empty());
                    }
                }
            }
        }
    }
    if let SnapshotKind::None = snapshot {
        error!("first breakpoint hit strange place");
        exit_elegantly(ExitProcessType::Error);
    }
    
    
    if include_init_phase {
        let mut block_id = emulator.modules_mut().blocks(
            Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, pc: u64| -> Option<u64> {
                bbl_translate_init_fuzz_phase(modules.qemu().first_cpu().unwrap(), pc); 
                Some(pc)
            })),
            Hook::Empty, 
            Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, id: u64| {
            bbl_debug(modules.qemu().first_cpu().unwrap()); 
        })));
        let mut devread_id : PostDeviceregReadHookId = emulator.modules_mut().devread(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : u32| {
            let fuzz_input = unsafe {&mut (*GLOB_INPUT) };
            post_io_read_init_fuzz_phase(base , offset ,size , data , handled,fuzz_input ,modules.qemu().first_cpu().unwrap());
        })));
        let mut devwrite_id : PreDeviceregWriteHookId = emulator.modules_mut().devwrite(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : *mut bool| {
            pre_io_write_init_fuzz_phase(base, offset,size , data , handled, modules.qemu().first_cpu().unwrap());
        })));
        let rdmsr_id = emulator.modules_mut().rdmsr(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, in_ecx: u32, out_eax: *mut u32, out_edx: *mut u32| {
            let fuzz_input = unsafe {&mut (*GLOB_INPUT) };
            rdmsr_init_fuzz_phase(in_ecx, out_eax, out_edx, fuzz_input);
        })));
        let wrmsr_id = emulator.modules_mut().wrmsr(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, in_ecx: u32, in_eax: *mut u32, in_edx: *mut u32| {
            wrmsr_common(in_ecx, in_eax, in_edx);
        })));
        let mut memrw_id = emulator.modules_mut().memrw(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, pc : GuestAddr, addr : GuestAddr, size : u64, out_addr : *mut GuestAddr, rw : u32 , value : u128| {
            let fuzz_input = unsafe {&mut (*GLOB_INPUT) };
            pre_memrw_init_fuzz_phase(pc, addr, size, out_addr,rw, value, fuzz_input, modules.qemu().first_cpu().unwrap());
        })));
        // let cpuid_id = emulator.modules_mut().cpuid(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, in_eax: u32, out_eax: *mut u32,out_ebx: *mut u32, out_ecx: *mut u32, out_edx: *mut u32| {
        //     let fuzz_input = unsafe {&mut (*GLOB_INPUT) };
        //     cpuid_init_fuzz_phase(in_eax, out_eax, out_ebx, out_ecx, out_edx, fuzz_input, modules.qemu().first_cpu().unwrap());
        // })));
    
        let mut module_index = 0;
        loop {
            let (seed_dirs, corpus_dir, crash_dir, snapshot_bin) = get_init_phase_dirs_for_replay(module_index, seed_path, corpus_path, crash_path, snapshot_path);
            if !corpus_dir.exists() || !snapshot_bin.exists() {
                break;
            }
            FuzzerSnapshot::restore_from_file(qemu, &snapshot_bin);
            let ret_coverage = init_phase_run(corpus_dir, &mut emulator); 
            module_index += 1;
        }
        block_id.remove(true);
        devread_id.remove(true);
        devwrite_id.remove(true);
        rdmsr_id.remove(true);
        wrmsr_id.remove(true);
        memrw_id.remove(true);
        // cpuid_id.remove(true);
    }

    info!("init phase finish, now start fuzz phase");
    

    let mut block_id = emulator.modules_mut().blocks(
        Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, pc: u64| -> Option<u64> {
            bbl_translate_smm_fuzz_phase(modules.qemu().first_cpu().unwrap(), pc); 
            Some(pc)
        })),
        Hook::Empty, 
        Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, id: u64| {
        bbl_debug(modules.qemu().first_cpu().unwrap()); 
    })));
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
    let wrmsr_id = emulator.modules_mut().wrmsr(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, in_ecx: u32, in_eax: *mut u32, in_edx: *mut u32| {
        wrmsr_common(in_ecx, in_eax, in_edx);
    })));
    
    FuzzerSnapshot::restore_from_file(qemu, &snapshot_bin_smi_phase);
    let ret_coverage = smm_phase_run(corpus_dir_smi_phase, &mut emulator);
    coverage.extend(ret_coverage);
    if let Some(coverage_log) = coverage_log {
        let mut file = File::create(&coverage_log).unwrap();
        for (time, bbl) in &coverage {
            writeln!(file, "{} {}", time, bbl);
        }
    }
    exit_elegantly(ExitProcessType::Ok);
}

fn report((seed_path,corpus_path, crash_path, snapshot_path) : (&PathBuf, &PathBuf, &PathBuf, &PathBuf)) {
    let args: Vec<String> = gen_ovmf_qemu_args();
    let env: Vec<(String, String)> = env::vars().collect();
    let qemu: Qemu = Qemu::init(args.as_slice(),env.as_slice()).unwrap();
    let mut emulator  = Emulator::new_with_qemu(qemu,
        tuple_list!(),
        NopEmulatorExitHandler,
        NopCommandManager)
        .unwrap();
    let cpu = qemu.first_cpu().unwrap();
    let (seed_dirs_smi_phase, corpus_dir_smi_phase, crash_dir_smi_phase, snapshot_bin_smi_phase) = get_smi_fuzz_phase_dirs_for_replay(seed_path, corpus_path, crash_path, snapshot_path);
    if !snapshot_bin_smi_phase.exists() {
        error!("snapshot not found, unable to replay");
        exit_elegantly(ExitProcessType::Ok);
    }
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
                    if sync_exit_reason == LIBAFL_QEMU_END_SMM_INIT_PREPARE {
                        info!("first breakpoint hit");
                    }
                }
            }
        }
    }

    FuzzerSnapshot::restore_from_file(qemu, &snapshot_bin_smi_phase);
    let _ = qemu_run_once(qemu, &FuzzerSnapshot::new_empty(),1000000000,false, false);
    exit_elegantly(ExitProcessType::Ok);
    
    let _ = smm_phase_run(PathBuf::new(), &mut emulator);
}