
mod snapshot_dev_filter;
use core::{ptr::addr_of_mut, time::Duration};
use std::borrow::Borrow;
use std::cell::UnsafeCell;
use std::mem::transmute;
use std::str::FromStr;
use std::{cell::RefCell, collections::HashMap, env, fmt::format, path::PathBuf, process, rc::Rc, vec};
use std::ptr::copy;
use rand::Rng;
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
use crate::snapshot_dev_filter::get_snapshot_dev_filter_list;
struct TestcaseInput {
    cursor : usize,
    input : *const u8,
    len : usize,
}

// static mut GLOB_INPUT : HashMap<&str, TestcaseInput> = HashMap::new();

static mut GLOB_INPUT : UnsafeCell<*mut HashMap<u128,TestcaseInput>> = UnsafeCell::new(std::ptr::null_mut() as *mut HashMap<u128,TestcaseInput>);
static mut EXEC_COUNT : UnsafeCell<u64> = UnsafeCell::new(0);
static NEW_STREAM : Lazy<Arc<Mutex<Vec<u128>>>> = Lazy::new( || Arc::new(Mutex::new(Vec::new())) );
static mut NUM_STREAMS : UnsafeCell<u64> = UnsafeCell::new(0);

fn get_exec_count() -> u64
{
    let exec_count;
    unsafe { exec_count =  *EXEC_COUNT.get(); }
    exec_count
}
fn set_exec_count(val :u64)
{
    unsafe { *EXEC_COUNT.get() =  val; }
}

fn post_io_read_common(pc : GuestReg, base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : u32) -> bool
{
    let mut ret = false;
    let addr = base + offset;
    
    // unsafe {
    //     let raw_input: *mut HashMap<u128,TestcaseInput> = *GLOB_INPUT.get();
    //     let id = (addr as u128) << 64 | (pc as u128);
    //     let id_entry = (*raw_input).get_mut(&id);

    //     if let Some(entry) = id_entry {
    //         if entry.cursor + size <= entry.len
    //         {
    //             data.copy_from(entry.input.byte_add(entry.cursor as usize), size);
    //             entry.cursor += size;
    //             ret = true;
    //         }
    //         else
    //         {
    //             ret = false;
    //         }
    //     }
    //     else
    //     {
    //         NEW_STREAM.lock().unwrap().push(id);
    //         ret = false
    //     }
    // }

    ret = true;
    let value = match size {
        1 => unsafe { *( data as *mut u8) as u64},
        2 => unsafe { *( data as *mut u16) as u64},
        4 => unsafe { *( data as *mut u32) as u64},
        8 => unsafe { *( data as *mut u64) as u64},
        _ => panic! ("post_io_read size error {:#x}!",size),
    };
    
    debug!("post_io_read {pc:#x} {addr:#x} {size:#x} {value:#x}");

    
    ret

}

fn cpuid_common(pc : GuestReg, in_eax: u32, out_eax: *mut u32,out_ebx: *mut u32, out_ecx: *mut u32, out_edx: *mut u32)
{
    unsafe {
        let eax_info = *out_eax;
        let ebx_info = *out_ebx;
        let ecx_info = *out_ecx;
        let edx_info = *out_edx;
        debug!("cpuid {pc:#x} {in_eax:#x} {eax_info:#x} {ebx_info:#x} {ecx_info:#x} {edx_info:#x}");
    }
}

fn rdmsr_common(pc : GuestReg, in_ecx: u32, out_eax: *mut u32, out_edx: *mut u32)
{
    unsafe {
        let eax_info = *out_eax;
        let edx_info = *out_edx;
        debug!("rdmsr {pc:#x} {in_ecx:#x} {eax_info:#x} {edx_info:#x}");
    }
}

fn wrmsr_common(pc : GuestReg, in_ecx: u32, in_eax: *mut u32, in_edx: *mut u32)
{
    unsafe {
        let eax_info = *in_eax;
        let edx_info = *in_edx;
        debug!("wrmsr {pc:#x} {in_ecx:#x} {eax_info:#x} {edx_info:#x}");
    }
}

fn pre_io_write_common(pc : GuestReg, base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : *mut bool)
{
    let value = match size {
        1 => unsafe { *( data as *mut u8) as u64},
        2 => unsafe { *( data as *mut u16) as u64},
        4 => unsafe { *( data as *mut u32) as u64},
        8 => unsafe { *( data as *mut u64) as u64},
        _ => panic! ("pre_io_write size error {:#x}!",size),
    };
    let addr = base + offset;
    debug!("pre_io_write {pc:#x} {addr:#x} {size:#x} {value:#x}");
}

fn backdoor_common(cmd : u64 , arg1 : u64, arg2 : u64, arg3 : u64)
{
    match cmd {
        9 => unsafe { 
            *NUM_STREAMS.get() =  arg1; 
            debug!("backdoor set num stream {:#x}\n",arg1);
        },
        10 => {
            debug!("backdoor write stream data {:#x}\n",arg1);
        },
        _ => { 
            panic!("backdoor wrong cmd {:#x}\n",cmd); 
        },
    };
}


fn qemu_run_til_start(qemu : &mut Qemu, cpu : &mut CPU)
{
    unsafe {
        let qemu_exit_reason = qemu.run();
        if let Ok(qemu_exit_reason) = qemu_exit_reason
        {
            if let QemuExitReason::SyncExit = qemu_exit_reason
            {
                let cmd : GuestReg = cpu.read_reg(Regs::Rax).unwrap();
                if cmd == 6
                {
                    if (*NUM_STREAMS.get()) != 0 {
                        debug!("qemu_run_til_start returned num_stream {:#x}\n",(*NUM_STREAMS.get()));
                        return;
                    }
                    else {
                        panic!("qemu_run_til_start returned num_stream 0");
                    }
                }
                else {
                    panic!("qemu_run_til_start error cmd {:#x}\n",cmd);
                }
            }
        }
        panic!("qemu_run_til_start error reason\n");
    }
}

fn qemu_run_to_end(qemu : &mut Qemu, cpu : &mut CPU) ->ExitKind
{
    unsafe {
        let qemu_exit_reason = qemu.run();
        if let Ok(qemu_exit_reason) = qemu_exit_reason
        {
            if let QemuExitReason::SyncExit = qemu_exit_reason
            {
                let cmd : GuestReg = cpu.read_reg(Regs::Rax).unwrap();
                let arg1 : GuestReg = cpu.read_reg(Regs::Rdi).unwrap();
                debug!("qemu_run_to_end sync exit {:#x} {:#x}\n",cmd,arg1);
                if cmd == 4 {
                    if arg1 == 0 {
                        return ExitKind::Crash;
                    }
                    else {
                        return ExitKind::Ok; 
                    }
                }
                else {
                    return ExitKind::Ok; 
                }
                
            }
            else if let QemuExitReason::End(_) = qemu_exit_reason
            {
                debug!("qemu_run_to_end qemu end\n");
                return ExitKind::Ok;
            }
            else if let QemuExitReason::Breakpoint(_) = qemu_exit_reason
            {
                debug!("qemu_run_to_end qemu breakpoint\n");
                return ExitKind::Timeout;
            }
            else
            {
                debug!("qemu_run_to_end qemu exit error\n");
                return ExitKind::Ok;
            }
        }
        else
        {
            debug!("qemu_run_to_end get qemu exit reason error\n");
            return ExitKind::Ok;
        }
    }
}

fn gen_ovmf_qemu_args() -> Vec<String>
{
    let mut args: Vec<String> = Vec::new();
    args.push(String::from_str("qemu-system-x86_64").unwrap());
    args.push(String::from_str("-machine").unwrap());
    args.push(String::from_str("q35,smm=on,accel=tcg").unwrap());
    args.push(String::from_str("-global").unwrap());
    args.push(String::from_str("driver=cfi.pflash01,property=secure,value=on").unwrap());
    args.push(String::from_str("-drive").unwrap());
    args.push(String::from_str("if=pflash,format=raw,unit=0,file=/home/w/hd/uefi_fuzz/fuzzer/edk2/Build/OvmfX64/DEBUG_GCC5/FV/OVMF_CODE.fd,readonly=on").unwrap());
    args.push(String::from_str("-drive").unwrap());
    args.push(String::from_str("if=pflash,format=raw,unit=1,file=/home/w/hd/uefi_fuzz/fuzzer/edk2/Build/OvmfX64/DEBUG_GCC5/FV/OVMF_VARS.fd").unwrap());
    args.push(String::from_str("-hda").unwrap());
    args.push(String::from_str("/home/w/hd/uefi_fuzz/fuzzer/run/smmfuzz.img").unwrap());
    args.push(String::from_str("-debugcon").unwrap());
    args.push(String::from_str("file:debug.log").unwrap());
    args.push(String::from_str("-global").unwrap());
    args.push(String::from_str("isa-debugcon.iobase=0x402").unwrap());
    args.push(String::from_str("-nographic").unwrap());
    args
}

#[allow(clippy::too_many_lines)]
fn main() {
    env_logger::init();
    let corpus_dirs = [PathBuf::from("./corpus")];
    let objective_dir = PathBuf::from("./crashes");
    let timeout = Duration::from_secs(1000);
    let args: Vec<String> = gen_ovmf_qemu_args();
    

    let env: Vec<(String, String)> = env::vars().collect();
    let mut qemu = Qemu::init(args.as_slice(),env.as_slice()).unwrap();
    let mut emulator = Emulator::new_with_qemu(qemu,
        tuple_list!(EdgeCoverageModule::default()),
        NopEmulatorExitHandler,
        NopCommandManager)
        .unwrap();
    let mut current_cpu = emulator.qemu().first_cpu().unwrap();


    let backdoor_id = emulator.modules_mut().backdoor(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, addr : GuestAddr| {
        let pc : GuestReg = current_cpu.read_reg(Regs::Pc).unwrap();

        let cmd : GuestReg = current_cpu.read_reg(Regs::Rax).unwrap();
        let arg1 : GuestReg = current_cpu.read_reg(Regs::Rdi).unwrap();
        let arg2 : GuestReg = current_cpu.read_reg(Regs::Rsi).unwrap();
        let arg3 : GuestReg = current_cpu.read_reg(Regs::Rdx).unwrap();
        backdoor_common(cmd, arg1, arg2, arg3);
    })));
    
    qemu_run_til_start(&mut qemu, &mut current_cpu);
    // let devices = qemu.list_devices();
    // println!("{:?}",devices);  
    let dev_filter = DeviceSnapshotFilter::DenyList(get_snapshot_dev_filter_list());
    let snap = emulator.create_fast_snapshot_filter(true,&dev_filter);
    debug!("take the first snapshot done");
    unsafe { emulator.restore_fast_snapshot(snap); }
    debug!("restore the first snapshot done");


    let block_id : BlockHookId = emulator.modules_mut().blocks(Hook::Function(gen_hashed_block_ids::<_, _>), Hook::Empty, 
        Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, id: u64| {
                let pc : GuestReg = current_cpu.read_reg(Regs::Pc).unwrap();
                let eax : GuestReg = current_cpu.read_reg(Regs::Rax).unwrap();
                let rdi : GuestReg = current_cpu.read_reg(Regs::Rdi).unwrap();
                trace!("bbl-> {pc:#x} {eax:#x} {rdi:#x}");
                if get_exec_count() > 500000000 {
                    
                    current_cpu.trigger_breakpoint();
                }
                set_exec_count(get_exec_count() + 1);
                
    })));
    let devread_id : PostDeviceregReadHookId = emulator.modules_mut().devread(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : u32| {

        let pc : GuestReg = current_cpu.read_reg(Regs::Pc).unwrap();
        let read_ok = post_io_read_common(pc , base , offset ,size , data , handled);
        if !read_ok{
            current_cpu.trigger_breakpoint();
        }
    })));
    let devwrite_id : PreDeviceregWriteHookId = emulator.modules_mut().devwrite(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : *mut bool| {
        let pc : GuestReg = current_cpu.read_reg(Regs::Pc).unwrap();
        pre_io_write_common(pc, base, offset,size , data , handled);
    })));
    let cpuid_id = emulator.modules_mut().cpuid(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, in_eax: u32, out_eax: *mut u32,out_ebx: *mut u32, out_ecx: *mut u32, out_edx: *mut u32| {
        let pc : GuestReg = current_cpu.read_reg(Regs::Pc).unwrap();
        cpuid_common(pc, in_eax,out_eax,out_ebx,out_ecx,out_edx);
    })));
    let rdmsr_id = emulator.modules_mut().rdmsr(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, in_ecx: u32, out_eax: *mut u32, out_edx: *mut u32| {
        let pc : GuestReg = current_cpu.read_reg(Regs::Pc).unwrap();
        rdmsr_common(pc, in_ecx, out_eax, out_edx);
    })));
    let wrmsr_id = emulator.modules_mut().wrmsr(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, in_ecx: u32, in_eax: *mut u32, in_edx: *mut u32| {
        let pc : GuestReg = current_cpu.read_reg(Regs::Pc).unwrap();
        wrmsr_common(pc, in_ecx, in_eax, in_edx);
    })));
    
    

    let mut harness = |input: & MultipartInput<BytesInput>, state: &mut QemuExecutorState<_, _, _, _>| {
        debug!("new run");
        set_exec_count(0);
        let mut inputs = HashMap::new();
        for (id, part) in input.iter()
        {
            let tmp = TestcaseInput {
                cursor : 0,
                input: part.bytes().as_ptr() as *const u8,
                len : part.len(),
            };
            inputs.insert(*id, tmp);
        }
        unsafe {  
            *GLOB_INPUT.get() = &mut inputs as *mut HashMap<u128,TestcaseInput>;
        }

        
        let mut in_simulator = state.emulator_mut();
        let mut in_qemu = in_simulator.qemu();
        let mut in_cpu = in_qemu.first_cpu().unwrap();
        let exit_code;
        unsafe {
            exit_code = qemu_run_to_end(&mut in_qemu, &mut in_cpu);
            in_simulator.restore_fast_snapshot(snap);
        }
        
        exit_code
    };



    
    let mut initial_input = MultipartInput::<BytesInput>::new();
    for i in 0..(unsafe { *NUM_STREAMS.get() } as usize)
    {
        initial_input.add_part((i + 1) as u128, BytesInput::new(vec![0x00,0x00,0x00,0x00]));
    }
    
    let mut init_seed_path = PathBuf::new(); 
    init_seed_path.push(corpus_dirs[0].clone());
    init_seed_path.push(PathBuf::from("init.bin"));
    initial_input.to_file(init_seed_path).unwrap();
    


    let mut edges_observer = unsafe {
        HitcountsMapObserver::new(VariableMapObserver::from_mut_slice(
            "edges",
            OwnedMutSlice::from_raw_parts_mut(edges_map_mut_ptr(), EDGES_MAP_SIZE_IN_USE),
            addr_of_mut!(MAX_EDGES_FOUND),  
        ))
        .track_indices()
    };

    // Create an observation channel to keep track of the execution time
    let time_observer = TimeObserver::new("time");

    
    let stream_observer = StreamObserver::new("stream", unsafe {Arc::clone(&NEW_STREAM)});
    // Feedback to rate the interestingness of an input
    // This one is composed by two Feedbacks in OR
    let mut feedback = feedback_or!(
        // New maximization map feedback linked to the edges observer and the feedback state
        MaxMapFeedback::new(&edges_observer),
        // Time feedback, this one does not need a feedback state
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
        timeout,
    )
    .expect("Failed to create QemuExecutor");

    let mut cmplogob = CmpLogObserver::new("cmplogob", true);
    
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
    fuzzer
            .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
            .unwrap();
    
}
