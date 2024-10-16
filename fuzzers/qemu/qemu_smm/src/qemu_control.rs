use libafl_qemu::{Qemu, QemuExitReason,QemuExitError};
use log::info;
use crate::common_hooks::*;
use crate::fuzzer_snapshot::*;
pub fn qemu_run_once(qemu : Qemu, snapshot : & FuzzerSnapshot, timeout : u64) -> Result<QemuExitReason, libafl_qemu::QemuExitError> {
    unsafe {
        set_exec_count(0);
        set_num_timeout_bbl(timeout);
        if ! snapshot.is_empty() {
            snapshot.restore_fuzz_snapshot(qemu);
        }
        let ret = qemu.run();
        ret
    }
}