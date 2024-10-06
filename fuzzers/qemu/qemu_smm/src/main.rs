
mod qemu_args;
mod sparse_memory;
mod cpu_hooks;
mod exit_qemu;
mod init_fuzz_phase;
mod smm_fuzz_phase;
mod stream_input;
mod common_hooks;
mod config;
use crate::qemu_args::*;
use crate::init_fuzz_phase::*;


use libafl_qemu::Qemu;
use std::env;
// static mut GLOB_INPUT : UnsafeCell<*mut HashMap<u128,StreamInput>> = UnsafeCell::new(std::ptr::null_mut() as *mut HashMap<u128,StreamInput>);
// static mut EXEC_COUNT : UnsafeCell<u64> = UnsafeCell::new(0);
// static NEW_STREAM : Lazy<Arc<Mutex<Vec<u128>>>> = Lazy::new( || Arc::new(Mutex::new(Vec::new())) );
// static mut NUM_STREAMS : UnsafeCell<u64> = UnsafeCell::new(0);








// fn qemu_run_til_start(qemu : &mut Qemu, cpu : &mut CPU)
// {
//     unsafe {
//         let qemu_exit_reason = qemu.run();
//         if let Ok(qemu_exit_reason) = qemu_exit_reason
//         {
//             if let QemuExitReason::SyncExit = qemu_exit_reason
//             {
//                 let cmd : GuestReg = cpu.read_reg(Regs::Rax).unwrap();
//                 if cmd == 6
//                 {
//                     if (*NUM_STREAMS.get()) != 0 {
//                         debug!("qemu_run_til_start returned num_stream {:#x}",(*NUM_STREAMS.get()));
//                         return;
//                     }
//                     else {
//                         panic!("qemu_run_til_start returned num_stream 0");
//                     }
//                 }
//                 else {
//                     panic!("qemu_run_til_start error cmd {:#x}",cmd);
//                 }
//             }
//         }
//         panic!("qemu_run_til_start error reason");
//     }
// }






#[allow(clippy::too_many_lines)]
fn main() {
    env_logger::init();
    let args: Vec<String> = gen_ovmf_qemu_args();
    let env: Vec<(String, String)> = env::vars().collect();
    let qemu = Qemu::init(args.as_slice(),env.as_slice()).unwrap();


    let smm_fuzz_snapshot = init_fuzz(qemu);
    
    // qemu_run_til_start(&mut qemu, &mut current_cpu);
    // let devices = qemu.list_devices();
    // println!("{:?}",devices);  
    // let dev_filter = DeviceSnapshotFilter::DenyList(get_snapshot_dev_filter_list());
    // let snap = emulator.create_fast_snapshot_filter(true,&dev_filter);
    // debug!("take the first snapshot done");
    // unsafe { emulator.restore_fast_snapshot(snap); }
    // debug!("restore the first snapshot done");

    // let backdoor_id = emulator.modules_mut().backdoor(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, addr : GuestAddr| {
    //     let pc : GuestReg = current_cpu.read_reg(Regs::Pc).unwrap();
        
    //     let cmd : GuestReg = current_cpu.read_reg(Regs::Rax).unwrap();
    //     let arg1 : GuestReg = current_cpu.read_reg(Regs::Rdi).unwrap();
    //     let arg2 : GuestReg = current_cpu.read_reg(Regs::Rsi).unwrap();
    //     let arg3 : GuestReg = current_cpu.read_reg(Regs::Rdx).unwrap();
    //     backdoor_common(modules.qemu(), cmd, arg1, arg2, arg3);
    // })));
    // let block_id : BlockHookId = emulator.modules_mut().blocks(Hook::Function(gen_hashed_block_ids::<_, _>), Hook::Empty, 
    //     Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, id: u64| {
    //             let pc : GuestReg = current_cpu.read_reg(Regs::Pc).unwrap();
    //             let eax : GuestReg = current_cpu.read_reg(Regs::Rax).unwrap();
    //             let rdi : GuestReg = current_cpu.read_reg(Regs::Rdi).unwrap();
    //             trace!("bbl-> {pc:#x} {eax:#x} {rdi:#x}");
    //             if get_exec_count() > 500000000 {
                    
    //                 current_cpu.trigger_breakpoint();
    //             }
    //             set_exec_count(get_exec_count() + 1);
                
    // })));
    // let devread_id : PostDeviceregReadHookId = emulator.modules_mut().devread(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : u32| {

    //     let pc : GuestReg = current_cpu.read_reg(Regs::Pc).unwrap();
    //     let read_ok = post_io_read_common(pc , base , offset ,size , data , handled);
    //     if !read_ok{
    //         current_cpu.trigger_breakpoint();
    //     }
    // })));
    // let devwrite_id : PreDeviceregWriteHookId = emulator.modules_mut().devwrite(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : *mut bool| {
    //     let pc : GuestReg = current_cpu.read_reg(Regs::Pc).unwrap();
    //     pre_io_write_common(pc, base, offset,size , data , handled);
    // })));
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
    // let memrw_id = emulator.modules_mut().memrw(Hook::Closure(Box::new(move |modules, _state: Option<&mut _>, pc : GuestAddr, addr : GuestAddr, size : u64, out_addr : *mut GuestAddr | {
    //     pre_memrw_common(pc, addr, size, out_addr);
    // })));
    
    

    // let mut harness = |input: & MultipartInput<BytesInput>, state: &mut QemuExecutorState<_, _, _, _>| {
        // debug!("new run");
        // set_exec_count(0);
        // set_xxx(0);
        // let mut inputs = HashMap::new();
        // for (id, part) in input.iter()
        // {
        //     let tmp = StreamInput {
        //         cursor : 0,
        //         input: part.bytes().as_ptr() as *const u8,
        //         len : part.len(),
        //     };
        //     inputs.insert(*id, tmp);
        // }
        // unsafe {  
        //     *GLOB_INPUT.get() = &mut inputs as *mut HashMap<u128,StreamInput>;
        // }

        
        // let mut in_simulator = state.emulator_mut();
        // let mut in_qemu = in_simulator.qemu();
        // let mut in_cpu = in_qemu.first_cpu().unwrap();
        // let exit_code;
        // unsafe {
        //     exit_code = qemu_run_to_end(&mut in_qemu, &mut in_cpu);
        //     in_simulator.restore_fast_snapshot(snap);
        // }
        
        // exit_code
    // };



    
    // let mut initial_input = MultipartInput::<BytesInput>::new();
    // for i in 0..(unsafe { *NUM_STREAMS.get() } as usize)
    // {
    //     initial_input.add_part((i + 1) as u128, BytesInput::new(vec![0x00,0x00,0x00,0x00]));
    // }
    
    // let mut init_seed_path = PathBuf::new(); 
    // init_seed_path.push(corpus_dirs[0].clone());
    // init_seed_path.push(PathBuf::from("init.bin"));
    // initial_input.to_file(init_seed_path).unwrap();
    


    // let mut edges_observer = unsafe {
    //     HitcountsMapObserver::new(VariableMapObserver::from_mut_slice(
    //         "edges",
    //         OwnedMutSlice::from_raw_parts_mut(edges_map_mut_ptr(), EDGES_MAP_SIZE_IN_USE),
    //         addr_of_mut!(MAX_EDGES_FOUND),  
    //     ))
    //     .track_indices()
    // };

    // // Create an observation channel to keep track of the execution time
    // let time_observer = TimeObserver::new("time");

    
    // let stream_observer = StreamObserver::new("stream", unsafe {Arc::clone(&NEW_STREAM)});
    // // Feedback to rate the interestingness of an input
    // // This one is composed by two Feedbacks in OR
    // let mut feedback = feedback_or!(
    //     // New maximization map feedback linked to the edges observer and the feedback state
    //     MaxMapFeedback::new(&edges_observer),
    //     // Time feedback, this one does not need a feedback state
    //     TimeFeedback::new(&time_observer),
    //     StreamFeedback::new(&stream_observer),
    // );
    
    // // A feedback to choose if an input is a solution or not
    // let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

    // let mut state = StdState::new(
    //     StdRand::with_seed(current_nanos()),
    //     CachedOnDiskCorpus::<MultipartInput<BytesInput>>::new(corpus_dirs[0].clone(),10 * 4096).unwrap(),
    //     CachedOnDiskCorpus::<MultipartInput<BytesInput>>::new(objective_dir,10 * 4096).unwrap(),
    //     &mut feedback,
    //     // Same for objective feedbacks
    //     &mut objective,
    // ).unwrap();

    
    
    

    
    // let mon = SimpleMonitor::new(|s| info!("{s}"));
    // let mut mgr = SimpleEventManager::new(mon);
    // let scheduler = PowerQueueScheduler::new(&mut state, &mut edges_observer, PowerSchedule::FAST);
    // let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // let mut executor = StatefulQemuExecutor::new(
    //     &mut emulator,
    //     &mut harness,
    //     tuple_list!(edges_observer, time_observer,stream_observer),
    //     &mut fuzzer,
    //     &mut state,
    //     &mut mgr,
    //     timeout,
    // )
    // .expect("Failed to create QemuExecutor");

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

    // if state.must_load_initial_inputs() {
    //     state
    //         .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &corpus_dirs)
    //         .unwrap_or_else(|_| {
    //             info!("Failed to load initial corpus at {:?}", &corpus_dirs);
    //             process::exit(0);
    //         });
    //         info!("We imported {} inputs from disk.", state.corpus().count());
    // }
    // let mutator = StdScheduledMutator::new(havoc_mutations());
    // let mut stages = tuple_list!(StdMutationalStage::new(mutator));
    // fuzzer
    //         .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
    //         .unwrap();
    
}
