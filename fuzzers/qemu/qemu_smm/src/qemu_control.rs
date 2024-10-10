use libafl_qemu::{Qemu, QemuExitReason,QemuExitError};
use crate::common_hooks::*;
use crate::fuzzer_snapshot::*;
pub fn qemu_run_once(qemu : Qemu, snapshot : & FuzzerSnapshot) -> Result<QemuExitReason, libafl_qemu::QemuExitError> {
    unsafe {
        set_exec_count(0);
        if ! snapshot.is_empty() {
            snapshot.restore_fuzz_snapshot(qemu);
        }
        qemu.run()
    }
}