use crate::common_hooks::*;
use libafl_qemu::{FastSnapshotPtr, Qemu};
use libafl_qemu_sys::QEMUFile;
use crate::qemu_args::*;
use libafl_qemu::DeviceSnapshotFilter;
use libafl_qemu::Regs;
use libafl_qemu::GuestReg;

pub struct FuzzerSnapshot {
    qemu_snapshot : Option<FastSnapshotPtr>,
}

pub enum SnapshotKind {
    None,
    StartOfUefiSnap(FuzzerSnapshot),
    StartOfSmmInitSnap(FuzzerSnapshot),
    EndOfSmmInitSnap(FuzzerSnapshot),
    StartOfSmmModuleSnap(FuzzerSnapshot),
    StartOfSmmFuzzSnap(FuzzerSnapshot),
}


impl FuzzerSnapshot {
    pub fn from_qemu(qemu : Qemu) -> Self {
        let dev_filter = DeviceSnapshotFilter::DenyList(get_snapshot_dev_filter_list());
        let qemu_snap = qemu.create_fast_snapshot_filter(true, &dev_filter);
        unsafe {
            FuzzerSnapshot {
                qemu_snapshot : Some(qemu_snap),
            }
        }
    }
    pub fn new_empty() -> Self {
        FuzzerSnapshot {
            qemu_snapshot : None,
        }
    }
    pub fn is_empty(&self) -> bool {
        self.qemu_snapshot.is_none()
    }
    pub fn delete(&self, qemu : Qemu) {
        if let Some(snap) = self.qemu_snapshot {
            qemu.delete_fast_snapshot(snap);
        }
    }
    pub fn restore_fuzz_snapshot(&self, qemu : Qemu, full_root_restore : bool) {
        unsafe {
            qemu.restore_fast_snapshot(self.qemu_snapshot.unwrap(), full_root_restore);
        }
    }
}
