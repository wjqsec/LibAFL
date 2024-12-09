use libafl_qemu::{Qemu, QemuExitReason,QemuExitError};
use log::info;
use once_cell::sync::Lazy;
use std::sync::{Arc, Mutex};
use crate::common_hooks::*;
use crate::fuzzer_snapshot::*;
use crate::stream_input::*;
use libafl_qemu::GuestReg;
use libafl_qemu::Regs;


pub static STREAM_FEEDBACK : Lazy<Arc<Mutex<Vec<(u128,bool,usize,Option<Vec<u8>>,Vec<u8>,usize,u8)>>>> = Lazy::new( || Arc::new(Mutex::new(Vec::new())));

fn post_fuzz_input_process() {
    if !unsafe { GLOB_INPUT.is_null() } {
        let fuzz_input = unsafe {&mut (*GLOB_INPUT) };
        let streams = fuzz_input.get_streams();
        for (id, input) in streams.iter() {
            if input.is_new_stream() {
                STREAM_FEEDBACK.lock().unwrap().push((*id, true, input.get_used(), input.get_new_stream(), input.get_append_stream(), input.get_limit().unwrap(), input.get_weight()));
            } else {
                STREAM_FEEDBACK.lock().unwrap().push((*id, false, input.get_used(), input.get_new_stream(), input.get_append_stream(), 0, 0));
            }
        }
    }
    unsafe {
        GLOB_INPUT = std::ptr::null_mut() as *mut StreamInputs;
    }
}

pub fn qemu_run_once(qemu : Qemu, snapshot : & FuzzerSnapshot, timeout : u64, restore_whole_fuzz_snapshot : bool, fuzz : bool) -> (Result<QemuExitReason, libafl_qemu::QemuExitError>, GuestReg, GuestReg, GuestReg, GuestReg, GuestReg) {
    unsafe {
        let cpu = qemu.first_cpu().unwrap();
        set_exec_count(0);
        set_num_timeout_bbl(timeout);
        if !snapshot.is_empty() {
            snapshot.restore_fuzz_snapshot(qemu, restore_whole_fuzz_snapshot);
        }
        IN_FUZZ = fuzz;
        let qemu_exit_reason = qemu.run();
        IN_FUZZ = false;
        post_fuzz_input_process();
        let pc : GuestReg = cpu.read_reg(Regs::Rip).unwrap();
        let cmd : GuestReg = cpu.read_reg(Regs::Rax).unwrap();
        let sync_exit_reason : GuestReg = cpu.read_reg(Regs::Rdi).unwrap();
        let arg1 : GuestReg = cpu.read_reg(Regs::Rsi).unwrap();
        let arg2 : GuestReg = cpu.read_reg(Regs::Rdx).unwrap();
        (qemu_exit_reason, pc, cmd, sync_exit_reason, arg1, arg2)
    }
}