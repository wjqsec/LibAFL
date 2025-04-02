use core::{ptr::addr_of_mut, time::Duration};
use std::cell::UnsafeCell;
use std::fmt::format;
use std::path::Path;
use std::str::FromStr;
use std::{path::PathBuf, process};
use libafl::corpus::{CorpusId, HasCurrentCorpusId, HasTestcase, Testcase};
use libafl::events::ProgressReporter;
use libafl::state::{HasSolutions, HasStartTime};
use libafl_bolts::math;
use log::*;
use libafl_bolts::{
    current_time, impl_serdeany, tuples::{Handle, Handled, MatchNameRef}, Named
};
use std::ptr;
use serde::{Serialize, Deserialize};
use libafl::prelude::InMemoryCorpus;
use libafl::{
    corpus::Corpus, executors::ExitKind, feedback_or, feedback_or_fast, feedbacks::{AflMapFeedback, CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback}, fuzzer::{Fuzzer, StdFuzzer}, inputs::{BytesInput, Input}, mutators::scheduled::{havoc_mutations, StdScheduledMutator}, observers::{stream::StreamObserver, CanTrack, HitcountsMapObserver, TimeObserver, VariableMapObserver}, prelude::{powersched::PowerSchedule, OnDiskCorpus, CachedOnDiskCorpus, PowerQueueScheduler, QueueScheduler, SimpleEventManager, SimpleMonitor}, stages::StdMutationalStage, state::{HasCorpus, StdState}
};
use libafl::mutators::Tokens;
use libafl::corpus::ondisk::*;
use libafl::feedbacks::stream::StreamFeedback;
use libafl::inputs::multi::MultipartInput;
use std::sync::{Arc, Mutex};
use std::{error, fs};
use std::fs::File;
use serde_json::Value;
use std::io::BufReader;
use std::io::{Read, Write};
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
use crate::smi_info::*;
use crate::smm_fuzz_qemu_cmds::*;

static mut TIMEOUT_TIMES : u64 = 0;
static mut END_TIMES : u64 = 0;
static mut CRASH_TIMES : u64 = 0;
static mut STREAM_OVER_TIMES : u64 = 0;
static mut ASSERT_TIMES : u64 = 0;


const SMI_FUZZ_TIMEOUT_BBL : u64 = 200000;

fn gen_init_random_seed(dir : &PathBuf) {
    for i in 0..get_num_smi_group() {
        let mut initial_input = MultipartInput::<BytesInput>::new();
        initial_input.add_part(SMI_GROUP_INDEX_MASK as u128, BytesInput::new(vec![i as u8]), 1, 0);
        let init_seed_path = dir.clone().join(format!("init_{}.bin",i));
        initial_input.to_file(init_seed_path).unwrap();
    }
    
}
fn add_uefi_fuzz_token(state : &mut StdState<MultipartInput<BytesInput>, CachedOnDiskCorpus<MultipartInput<BytesInput>>, libafl_bolts::prelude::RomuDuoJrRand, OnDiskCorpus<MultipartInput<BytesInput>>>) {
    let mut tokens = Tokens::new();

    for i in 0..10 {
        tokens.add_token(&(i as u8).to_le_bytes().to_vec());
        tokens.add_token(&(i as u16).to_le_bytes().to_vec());
        tokens.add_token(&(i as u32).to_le_bytes().to_vec());
        tokens.add_token(&(i as u64).to_le_bytes().to_vec());
    }
    for i in 0..40 {
        tokens.add_token(&(unsafe {REDZONE_BUFFER_AADR} as u64).to_le_bytes().to_vec());
    }
    state.add_metadata(tokens);
}

fn run_to_smm_fuzz_point(qemu : Qemu, cpu : CPU) -> SnapshotKind {
    // run to the start cause we are now at the start of the smm fuzz driver
    let (qemu_exit_reason, pc, cmd, sync_exit_reason, arg1, arg2) = qemu_run_once(qemu, &FuzzerSnapshot::new_empty(),10000000000, true, false);
    if let Ok(ref qemu_exit_reason) = qemu_exit_reason {
        if let QemuExitReason::SyncExit = qemu_exit_reason {
            if cmd == LIBAFL_QEMU_COMMAND_END {
                if sync_exit_reason == LIBAFL_QEMU_END_SMM_FUZZ_START {
                    return SnapshotKind::StartOfSmmFuzzSnap(FuzzerSnapshot::from_qemu(qemu));
                }
            }
        }
    }
    return SnapshotKind::None;
}


pub fn smm_phase_fuzz(seed_dirs : PathBuf, corpus_dir : PathBuf, objective_dir : PathBuf, emulator: &mut Emulator<NopCommandManager, NopEmulatorExitHandler, (EdgeCoverageModule, (CmpLogModule, ())), StdState<MultipartInput<BytesInput>, CachedOnDiskCorpus<MultipartInput<BytesInput>>, libafl_bolts::prelude::RomuDuoJrRand, OnDiskCorpus<MultipartInput<BytesInput>>>>, fuzz_time : Option<Duration>)
{
    let qemu = emulator.qemu();
    let cpu: CPU = qemu.first_cpu().unwrap();
    
    let mut snapshot= FuzzerSnapshot::new_empty();
    if let SnapshotKind::StartOfSmmFuzzSnap(s) = run_to_smm_fuzz_point(qemu, cpu) {
        snapshot = s;
    } else {
        error!("run to fuzz point error");
        exit_elegantly(ExitProcessType::Error);
    }
    gen_init_random_seed(&seed_dirs);

    emulator.modules_mut().first_exec_all();
    let mut harness = |input: & MultipartInput<BytesInput>, state: &mut QemuExecutorState<_, _, _, _>| {
        let mut inputs = StreamInputs::from_multiinput(input);
        unsafe {  
            GLOB_INPUT = (&mut inputs) as *mut StreamInputs;
        }
        let in_simulator = state.emulator_mut();
        let in_qemu: Qemu = in_simulator.qemu();
        let in_cpu: CPU = in_qemu.first_cpu().unwrap();
        let (qemu_exit_reason, pc, cmd, sync_exit_reason, arg1, arg2) = qemu_run_once(in_qemu, &snapshot, SMI_FUZZ_TIMEOUT_BBL,false, true);
        let exit_code;
        if let Ok(qemu_exit_reason) = qemu_exit_reason
        {
            if let QemuExitReason::SyncExit = qemu_exit_reason  {
                if cmd == LIBAFL_QEMU_COMMAND_END {
                    match sync_exit_reason {
                        LIBAFL_QEMU_END_CRASH => {
                            unsafe {
                                CRASH_TIMES += 1;
                            }
                            exit_code = ExitKind::Crash;
                        },
                        LIBAFL_QEMU_END_SMM_FUZZ_END => {
                            unsafe {
                                END_TIMES += 1;
                            }
                            exit_code = ExitKind::Ok;
                        },
                        | LIBAFL_QEMU_END_SMM_ASSERT => {
                            unsafe {ASSERT_TIMES += 1;}
                            exit_code = ExitKind::Ok;
                        },
                        _ => {
                            error!("exit error with sync exit arg {:#x}",sync_exit_reason);
                            exit_code = ExitKind::Ok;
                        }
                    }
                }
                else {
                    error!("exit error with sync exit cmd {:#x}",cmd);
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
            else if let QemuExitReason::Crash = qemu_exit_reason {
                unsafe {
                    CRASH_TIMES += 1;
                }
                exit_code = ExitKind::Crash;
            }
            else if let QemuExitReason::End(_) = qemu_exit_reason {
                exit_code = ExitKind::Ok;
            }
            else if let QemuExitReason::Breakpoint(_) = qemu_exit_reason {
                error!("Unexpected breakpoint hit");
                exit_code = ExitKind::Ok;
            }
            else {
                error!("Unexpected exit");
                exit_code = ExitKind::Ok;
            }
        }
        else    {
            error!("exit {:?}",qemu_exit_reason);
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
        SmiGlobalFoundTimeMetadataFeedback::new(),
    );
    
    // A feedback to choose if an input is a solution or not
    let mut objective = feedback_or!(
        CrashFeedback::new(),
        StreamFeedback::new(&stream_observer),
        SmiGlobalFoundTimeMetadataFeedback::new(),
    );

    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        CachedOnDiskCorpus::<MultipartInput<BytesInput>>::new(corpus_dir.clone(),5 * 4096).unwrap(),
        OnDiskCorpus::<MultipartInput<BytesInput>>::new(objective_dir.clone()).unwrap(),
        &mut feedback,
        // Same for objective feedbacks
        &mut objective,
    ).unwrap();
    add_uefi_fuzz_token(&mut state);

    let mon = SimpleMonitor::new(|s| 
        info!("{s} end:{:?} stream:{:?} crash:{:?} timeout:{:?} assert:{:?}", unsafe{END_TIMES}, unsafe{STREAM_OVER_TIMES}, unsafe{CRASH_TIMES}, unsafe{TIMEOUT_TIMES}, unsafe{ASSERT_TIMES})  
    );
    let mut mgr = SimpleEventManager::new(mon);
    let scheduler = PowerQueueScheduler::new(&mut state, &mut edges_observer, PowerSchedule::FAST);
    // let scheduler = QueueScheduler::new();
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
    
    let mutator = StdScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));
    let mut shadow_executor = ShadowExecutor::new(executor, tuple_list!(cmplog_observer));
    let i2s = StdMutationalStage::new(StdScheduledMutator::new(tuple_list!(
        I2SRandReplace::new()
    )));

    let mut stages = tuple_list!(ShadowTracingStage::new(&mut shadow_executor),i2s, StdMutationalStage::new(mutator));

    for i in 0..(state.corpus().last().unwrap().0 + 1) {
        let testcase = state.corpus().get(CorpusId::from(i)).unwrap().clone().take().clone();
        let smi_metadata_filename = format!(".{}.smi_metadata",testcase.filename().clone().unwrap());
        let smi_metadata_fullpath = PathBuf::from(testcase.file_path().clone().unwrap()).parent().unwrap().join(smi_metadata_filename.clone());
        smi_group_info_to_file(&smi_metadata_fullpath);
    }


    for i in 0..( state.corpus().last().unwrap().0 + 1) {
        let input = state.corpus().get(CorpusId::from(i)).unwrap().clone().take().clone().input().clone().unwrap();
        fuzzer.execute_input(&mut state, &mut shadow_executor, &mut mgr, &input);
        let _ = qemu_run_once(qemu, &FuzzerSnapshot::new_empty(),30000000, true, false);
    }

    loop {
        let num_corpus = state.corpus().last().unwrap().0;
        let mut num_solutions = None;
        if state.solutions().last().is_some() {
            num_solutions = Some(state.solutions().last().unwrap().0);
        }
        fuzzer.fuzz_one(&mut stages, &mut shadow_executor, &mut state, &mut mgr).unwrap();
        mgr.maybe_report_progress(&mut state, Duration::from_secs(60));
        for i in num_corpus..(state.corpus().last().unwrap().0 + 1) {
            let testcase = state.corpus().get(CorpusId::from(i)).unwrap().clone().take().clone();
            let smi_metadata_filename = format!(".{}.smi_metadata",testcase.filename().clone().unwrap());
            let smi_metadata_fullpath = PathBuf::from(testcase.file_path().clone().unwrap()).parent().unwrap().join(smi_metadata_filename.clone());
            smi_group_info_to_file(&smi_metadata_fullpath);
        }

        if num_solutions.is_some() {
            for i in num_solutions.unwrap()..(state.solutions().last().unwrap().0 + 1) {
                let testcase = state.solutions().get(CorpusId::from(i)).unwrap().clone().take().clone();
                let smi_metadata_filename = format!(".{}.smi_metadata",testcase.filename().clone().unwrap());
                let smi_metadata_fullpath = PathBuf::from(testcase.file_path().clone().unwrap()).parent().unwrap().join(smi_metadata_filename.clone());
                smi_group_info_to_file(&smi_metadata_fullpath);
            }
        } else {
            if let Some(end_num_solutions) = state.solutions().last() {
                for i in 0..(end_num_solutions.0 + 1) {
                    let testcase = state.solutions().get(CorpusId::from(i)).unwrap().clone().take().clone();
                    let smi_metadata_filename = format!(".{}.smi_metadata",testcase.filename().clone().unwrap());
                    let smi_metadata_fullpath = PathBuf::from(testcase.file_path().clone().unwrap()).parent().unwrap().join(smi_metadata_filename.clone());
                    smi_group_info_to_file(&smi_metadata_fullpath);
                }
            }
        }
        for i in num_corpus..( state.corpus().last().unwrap().0 + 1) {
            let input = state.corpus().get(CorpusId::from(i)).unwrap().clone().take().clone().input().clone().unwrap();
            fuzzer.execute_input(&mut state, &mut shadow_executor, &mut mgr, &input);
            let _ = qemu_run_once(qemu, &FuzzerSnapshot::new_empty(),30000000, true, false);
        }
        if ctrlc_pressed() {
            exit_elegantly(ExitProcessType::Ok);
        }
        if let Some(fuzz_time) = fuzz_time {
            if (current_time().as_secs() - state.start_time().as_secs()) > fuzz_time.as_secs() {
                info!("Fuzz {:?} Finished",fuzz_time);
                break;
            }
        }
    }

} 



pub fn smm_phase_run(input_corpus : PathBuf, emulator: &mut Emulator<NopCommandManager, NopEmulatorExitHandler, (), StdState<MultipartInput<BytesInput>, InMemoryCorpus<MultipartInput<BytesInput>>, libafl_bolts::prelude::RomuDuoJrRand, InMemoryCorpus<MultipartInput<BytesInput>>>>) -> Vec<(u128, usize)>
{
    let qemu = emulator.qemu();
    let cpu: CPU = qemu.first_cpu().unwrap();
    let mut snapshot= FuzzerSnapshot::new_empty();
    if let SnapshotKind::StartOfSmmFuzzSnap(s) = run_to_smm_fuzz_point(qemu, cpu) {
        snapshot = s;
    } else {
        error!("run to fuzz point error");
        exit_elegantly(ExitProcessType::Error);
    }
    emulator.modules_mut().first_exec_all();
    let mut harness = |input: & MultipartInput<BytesInput>, state: &mut QemuExecutorState<_, _, _, _>| {
        let mut inputs = StreamInputs::from_multiinput(input);
        unsafe {  
            GLOB_INPUT = (&mut inputs) as *mut StreamInputs;
        }
        let in_simulator = state.emulator_mut();
        let in_qemu: Qemu = in_simulator.qemu();
        let in_cpu = in_qemu.first_cpu().unwrap();
        let (qemu_exit_reason, pc, cmd, sync_exit_reason, arg1, arg2) = qemu_run_once(in_qemu, &snapshot, SMI_FUZZ_TIMEOUT_BBL,false, true);
        let exit_code;
        let rsp : GuestReg = in_cpu.read_reg(Regs::Rsp).unwrap();
        if let Ok(qemu_exit_reason) = qemu_exit_reason
        {
            if let QemuExitReason::SyncExit = qemu_exit_reason  {
                if cmd == LIBAFL_QEMU_COMMAND_END {
                    match sync_exit_reason {
                        LIBAFL_QEMU_END_CRASH => {
                            unsafe {CRASH_TIMES += 1;}
                            exit_code = ExitKind::Crash;
                            let mut rsp_data_buf : [u8; 8] = [0 ; 8];
                            unsafe {
                                in_cpu.read_mem(arg2,&mut rsp_data_buf);
                            }
                            let rsp_data = u64::from_le_bytes(rsp_data_buf);
                            info!("exit crash pc:{} rsp:{:#x} [rsp]:{}",get_readable_addr(arg1), arg2, get_readable_addr(rsp_data));
                        },
                        LIBAFL_QEMU_END_SMM_FUZZ_END => {
                            unsafe {END_TIMES += 1;}
                            exit_code = ExitKind::Ok;
                            info!("exit end");
                        },
                        | LIBAFL_QEMU_END_SMM_ASSERT => {
                            unsafe {ASSERT_TIMES += 1;}
                            exit_code = ExitKind::Ok;
                            info!("exit assert");
                        },
                        _ => {
                            error!("exit error with sync exit arg {:#x}",sync_exit_reason);
                            exit_code = ExitKind::Ok;
                        }
                    }
                }
                else {
                    error!("exit error with sync exit cmd {:#x}",cmd);
                    exit_code = ExitKind::Ok;
                }
            }
            else if let QemuExitReason::Timeout = qemu_exit_reason {
                unsafe {TIMEOUT_TIMES += 1;}
                exit_code = ExitKind::Timeout;
                info!("exit timeout pc:{} sp:{:#x}",get_readable_addr(pc), rsp);
            }
            else if let QemuExitReason::StreamNotFound = qemu_exit_reason {
                exit_code = ExitKind::Ok;
                info!("exit stream not found pc:{} sp:{:#x}",get_readable_addr(pc), rsp);
            }
            else if let QemuExitReason::StreamOutof = qemu_exit_reason {
                unsafe {STREAM_OVER_TIMES += 1;}
                exit_code = ExitKind::Ok;
                info!("exit stream over pc:{} sp:{:#x}",get_readable_addr(pc), rsp);
            }
            else if let QemuExitReason::Crash = qemu_exit_reason {
                unsafe {
                    CRASH_TIMES += 1;
                }
                exit_code = ExitKind::Crash;
                let mut rsp_data_buf : [u8; 8] = [0 ; 8];
                unsafe {
                    in_cpu.read_mem(rsp,&mut rsp_data_buf);
                }
                let rsp_data = u64::from_le_bytes(rsp_data_buf);
                info!("exit callout pc:{} sp:{:#x} [rsp]:{}",get_readable_addr(pc), rsp, get_readable_addr(rsp_data));
            }
            else if let QemuExitReason::End(_) = qemu_exit_reason {
                error!("ctrl-C");
                exit_code = ExitKind::Ok;
            }
            else if let QemuExitReason::Breakpoint(_) = qemu_exit_reason {
                error!("Unexpected breakpoint hit");
                exit_code = ExitKind::Ok;
            }
            else {
                error!("Unexpected exit");
                exit_code = ExitKind::Ok;
            }
        }
        else    {
            error!("exit {:?}",qemu_exit_reason);
            exit_code = ExitKind::Ok;
        }
            
        exit_code
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
        info!("{s} bbl:{:?} end:{:?} stream:{:?} crash:{:?} timeout:{:?} assert:{:?}",num_bbl_covered(), unsafe{END_TIMES}, unsafe{STREAM_OVER_TIMES}, unsafe{CRASH_TIMES}, unsafe{TIMEOUT_TIMES}, unsafe{ASSERT_TIMES})  
    );
    let mut mgr = SimpleEventManager::new(mon);
    let scheduler = QueueScheduler::new();
    // let scheduler = QueueScheduler::new();
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
    if input_corpus.is_dir() {
        let mut corpus_inputs = Vec::new();
            if let Ok(entries) = fs::read_dir(input_corpus.clone()) {
                for entry in entries {
                    if let Ok(entry) = entry {
                        let file_name = entry.file_name();
                        let file_name_str = file_name.to_string_lossy();
                        if !file_name_str.starts_with('.') {
                            info!("load {}",file_name_str);
                            let metadata_filename = format!(".{file_name_str}.metadata");
                            let metadata_fullpath = entry.path().parent().unwrap().join(metadata_filename);

                            let smi_metadata_filename = format!(".{file_name_str}.smi_metadata");
                            let smi_metadata_fullpath = entry.path().parent().unwrap().join(smi_metadata_filename);
                            corpus_inputs.push((entry.path().to_str().unwrap().to_string() , metadata_fullpath.to_str().unwrap().to_string(), smi_metadata_fullpath.to_str().unwrap().to_string(), 0));
                        }
                    }
                }
            }
            
            for input in corpus_inputs.iter_mut() {
                let contents = fs::read_to_string(input.1.clone()).unwrap();
                let config_json : Value = serde_json::from_str(&contents[..]).unwrap();
                let found_time = config_json.get("found_time").unwrap().as_str().unwrap().parse::<u128>().unwrap();
                input.3 = found_time;
            }
            corpus_inputs.sort_by( |a ,b| {
                a.3.cmp(&b.3)
            });
            for input in corpus_inputs.iter() {
                smi_group_info_from_file(&PathBuf::from(input.2.clone()));
                let input_testcase = MultipartInput::from_file(input.0.clone()).unwrap();
                info!("exec input {}",input.0.clone());
                fuzzer.execute_input(&mut state, &mut executor, &mut mgr, &input_testcase);
                info!("bbl {} {}",input.3, num_bbl_covered());
                ret.push((input.3, num_bbl_covered()));
                if ctrlc_pressed() {
                    exit_elegantly(ExitProcessType::Ok);
                } 
            }
    } else if input_corpus.is_file() {
        let input = MultipartInput::from_file(input_corpus.clone()).unwrap();
        info!("exec input {}",input_corpus.clone().to_str().unwrap());
        fuzzer.execute_input(&mut state, &mut executor, &mut mgr, &input);
    }     

    return ret;
}
