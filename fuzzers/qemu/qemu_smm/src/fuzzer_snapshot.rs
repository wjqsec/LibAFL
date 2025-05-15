use std::path::PathBuf;

use crate::common_hooks::*;
use crate::{exit_elegantly, ExitProcessType};
use libafl_qemu::{FastSnapshotPtr, Qemu};
use libafl_qemu_sys::QEMUFile;
use crate::qemu_args::*;
use libafl_qemu::DeviceSnapshotFilter;
use libafl_qemu::Regs;
use libafl_qemu::GuestReg;
use log::*;

use std::io::prelude::*;
use std::io;
use flate2::Compression;
use flate2::bufread::{ GzEncoder, GzDecoder};
use std::fs::File;
use std::io::BufReader;
use crate::fs::remove_file;
use crate::fs::rename;


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

fn compress_in_place(path: &PathBuf) -> std::io::Result<()> {
    // Read original file
    let mut input = File::open(path)?;
    let b = BufReader::new(input);
    let mut gz = GzEncoder::new(b, Compression::default());
    let mut compressed_data = Vec::new();
    gz.read_to_end(&mut compressed_data)?;
    // Temp file
    let tmp_path = path.with_extension("tmp");
    let mut tmp_file = File::create(&tmp_path)?;
    tmp_file.write_all(&compressed_data)?;
    tmp_file.flush()?;

    // Replace original
    remove_file(path)?;
    rename(tmp_path, path)?;

    Ok(())
}
fn decompress_in_place(path: &PathBuf) -> std::io::Result<()> {
    // Open and decompress
    info!("decompress {:?}",path);
    let input = File::open(path)?;
    let b = BufReader::new(input);
    let mut gz = GzDecoder::new(b);
    let mut decompressed_data = Vec::new();
    gz.read_to_end(&mut decompressed_data)?;

    // Write to a temporary file
    let tmp_path = path.with_extension("tmp");
    let mut tmp_file = File::create(&tmp_path)?;
    tmp_file.write_all(&decompressed_data)?;
    tmp_file.flush()?;

    // Replace original file
    remove_file(path)?;
    rename(tmp_path, path)?;

    Ok(())
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
    pub fn from_qemu_untrack(qemu : Qemu) -> Self {
        let dev_filter = DeviceSnapshotFilter::DenyList(get_snapshot_dev_filter_list());
        let qemu_snap = qemu.create_fast_snapshot_filter(false, &dev_filter);
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
        if full_root_restore {
            qemu.flush_jit();
        }
    }

    pub fn save_to_file(qemu : Qemu, filename : &PathBuf) {
        let dev_filter = DeviceSnapshotFilter::DenyList(get_snapshot_dev_filter_list());
        let ret = qemu.state_save_to_file(&dev_filter,filename.to_str().unwrap());
        if !ret {
            exit_elegantly(ExitProcessType::Error("save state to file error"));
        }
        let ret = compress_in_place(filename);
        if ret.is_err() {
            exit_elegantly(ExitProcessType::Error("compress state to file error"));
        }

    }

    pub fn restore_from_file(qemu : Qemu, filename : &PathBuf) {
        let ret = decompress_in_place(filename);
        if ret.is_err() {
            exit_elegantly(ExitProcessType::Error("decompress state to file error"));
        }
        let ret = qemu.state_restore_from_file(filename.to_str().unwrap());
        if !ret {
            exit_elegantly(ExitProcessType::Error("restore state from file error"));
        }
        let ret = compress_in_place(filename);
        if ret.is_err() {
            exit_elegantly(ExitProcessType::Error("compress state to file error"));
        }
    }
}
