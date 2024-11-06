use libafl_qemu::{Qemu, QemuExitReason,QemuExitError};
use log::info;
use once_cell::sync::Lazy;
use std::sync::{Arc, Mutex};
use crate::common_hooks::*;
use crate::fuzzer_snapshot::*;
use crate::stream_input::*;


pub static STREAM_FEEDBACK : Lazy<Arc<Mutex<Vec<(u128,bool,usize,Vec<u8>,usize)>>>> = Lazy::new( || Arc::new(Mutex::new(Vec::new())));


pub fn qemu_run_once(qemu : Qemu, snapshot : & FuzzerSnapshot, timeout : u64, restore_fuzz_snapshot : bool) -> Result<QemuExitReason, libafl_qemu::QemuExitError> {
    unsafe {
        set_exec_count(0);
        set_num_timeout_bbl(timeout);
        if ! snapshot.is_empty() {
            snapshot.restore_fuzz_snapshot(qemu, restore_fuzz_snapshot);
        }
        let ret = qemu.run();
        if unsafe {GLOB_INPUT != std::ptr::null_mut() as *mut StreamInputs} {
            let fuzz_input = unsafe {&mut (*GLOB_INPUT) };
            let streams = fuzz_input.get_streams();
            for (id, input) in streams.iter() {
                if input.is_tmp_generated() {
                    STREAM_FEEDBACK.lock().unwrap().push((*id,true,input.get_used(),fuzz_input.get_tmp_generated_stream(id), input.get_limit()));
                } else {
                    STREAM_FEEDBACK.lock().unwrap().push((*id,false,input.get_used(),Vec::new(), 0));
                }
            }
        }
        GLOB_INPUT = std::ptr::null_mut() as *mut StreamInputs;
        ret
    }
}