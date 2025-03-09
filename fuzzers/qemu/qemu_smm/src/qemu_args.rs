use std::vec::*;
use std::string::*;
use std::ffi::{CString, CStr};
use std::path::Path;
use once_cell::sync::Lazy;
use std::{path::PathBuf, process};

static mut OVMF_CODE_PATH : Lazy<PathBuf> = Lazy::new(|| {
    PathBuf::new()
});
static mut OVMF_VARS_PATH : Lazy<PathBuf> = Lazy::new(|| {
    PathBuf::new()
});
static mut QEMU_DEBUG_LOG_PATH : Lazy<PathBuf> = Lazy::new(|| {
    PathBuf::new()
});
pub fn set_ovmf_path(ovmf_code_path : &PathBuf, ovmf_var_path : &PathBuf, qemu_debug_log_path : &PathBuf)
{
    unsafe {
        OVMF_CODE_PATH.clone_from(ovmf_code_path);
        OVMF_VARS_PATH.clone_from(ovmf_var_path);
        QEMU_DEBUG_LOG_PATH.clone_from(qemu_debug_log_path);
    }
}

pub fn gen_ovmf_qemu_args() -> Vec<String>
{
    let project_dir = env!("CARGO_MANIFEST_DIR");
    let qemu_firmware_dir = Path::new(project_dir).join("qemu_firmware");
    let mut ret = vec![
        "qemu-system-x86_64".to_string(),
        "-machine".to_string(),
        "q35,smm=on,accel=tcg".to_string(),
        "-global".to_string(),
        "driver=cfi.pflash01,property=secure,value=on".to_string(),
        "-drive".to_string(),
        format!("if=pflash,format=raw,unit=0,file={},readonly=on",unsafe {OVMF_CODE_PATH.to_string_lossy().to_string()}).to_string(),
        "-drive".to_string(),
        format!("if=pflash,format=raw,unit=1,file={}",unsafe {OVMF_VARS_PATH.to_string_lossy().to_string()}).to_string(),
        "-global".to_string(),
        "isa-debugcon.iobase=0x402".to_string(),
        "-L".to_string(),
        qemu_firmware_dir.to_string_lossy().to_string(),
        "-serial".to_string(),
        "null".to_string(),
        "-global".to_string(),
        "mch.extended-tseg-mbytes=56".to_string(),
    ];
    if ! unsafe { QEMU_DEBUG_LOG_PATH.to_string_lossy().to_string().is_empty() } {
        ret.push("-debugcon".to_string());
        ret.push(format!("file:{}",unsafe {OVMF_VARS_PATH.to_string_lossy().to_string()}).to_string());
    }
    ret

}
pub fn get_snapshot_dev_filter_list() -> Vec<String>    
{
    vec![
        // CString::new("timer").unwrap().into_string().unwrap(),
        // CString::new("cpu_common").unwrap().into_string().unwrap(),
        // CString::new("cpu").unwrap().into_string().unwrap(),

        // CString::new("kvm-tpr-opt").unwrap().into_string().unwrap(),
        // CString::new("apic").unwrap().into_string().unwrap(),
        CString::new("pflash_cfi01").unwrap().into_string().unwrap(),
        CString::new("pflash_cfi01").unwrap().into_string().unwrap(),

        // CString::new("fw_cfg").unwrap().into_string().unwrap(),
        // CString::new("0000:00:00.0/mch").unwrap().into_string().unwrap(),
        // CString::new("PCIHost").unwrap().into_string().unwrap(),
        // CString::new("PCIBUS").unwrap().into_string().unwrap(),
        // CString::new("dma").unwrap().into_string().unwrap(),
        // CString::new("dma").unwrap().into_string().unwrap(),
        // CString::new("mc146818rtc").unwrap().into_string().unwrap(),

        // CString::new("0000:00:1f.0/ICH9LPC").unwrap().into_string().unwrap(),

        // CString::new("i8259").unwrap().into_string().unwrap(),
        // CString::new("i8259").unwrap().into_string().unwrap(),
        // CString::new("ioapic").unwrap().into_string().unwrap(),
        // CString::new("hpet").unwrap().into_string().unwrap(),
        // CString::new("i8254").unwrap().into_string().unwrap(),
        // CString::new("pcspk").unwrap().into_string().unwrap(),
        // CString::new("serial").unwrap().into_string().unwrap(),
        // CString::new("parallel_isa").unwrap().into_string().unwrap(),
        // CString::new("ps2kbd").unwrap().into_string().unwrap(),
        // CString::new("ps2mouse").unwrap().into_string().unwrap(),
        // CString::new("pckbd").unwrap().into_string().unwrap(),
        // CString::new("vmmouse").unwrap().into_string().unwrap(),
        // CString::new("port92").unwrap().into_string().unwrap(),

        // CString::new("0000:00:1f.2/ich9_ahci").unwrap().into_string().unwrap(),
        // CString::new("i2c_bus").unwrap().into_string().unwrap(),
        // CString::new("0000:00:1f.3/ich9_smb").unwrap().into_string().unwrap(),

        // CString::new("smbus-eeprom").unwrap().into_string().unwrap(),
        // CString::new("smbus-eeprom").unwrap().into_string().unwrap(),
        // CString::new("smbus-eeprom").unwrap().into_string().unwrap(),
        // CString::new("smbus-eeprom").unwrap().into_string().unwrap(),
        // CString::new("smbus-eeprom").unwrap().into_string().unwrap(),
        // CString::new("smbus-eeprom").unwrap().into_string().unwrap(),
        // CString::new("smbus-eeprom").unwrap().into_string().unwrap(),
        // CString::new("smbus-eeprom").unwrap().into_string().unwrap(),
        // CString::new("0000:00:01.0/vga").unwrap().into_string().unwrap(),
        // CString::new("0000:00:02.0/e1000e").unwrap().into_string().unwrap(),
        // CString::new("acpi_build").unwrap().into_string().unwrap(),
    ]
}