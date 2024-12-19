use std::vec::*;
use std::string::*;
use std::ffi::{CString, CStr};

const OVMF_MODE : &str = "RELEASE";
pub fn gen_ovmf_qemu_args(ovmf_code_path : &String, ovmf_var_path : &String) -> Vec<String>
{
    vec![
        "qemu-system-x86_64".to_string(),
        "-machine".to_string(),
        "q35,smm=on,accel=tcg".to_string(),
        "-global".to_string(),
        "driver=cfi.pflash01,property=secure,value=on".to_string(),
        "-drive".to_string(),
        format!("if=pflash,format=raw,unit=0,file={},readonly=on",ovmf_code_path).to_string(),
        "-drive".to_string(),
        format!("if=pflash,format=raw,unit=1,file={}",ovmf_var_path).to_string(),
        "-debugcon".to_string(),
        "file:debug.log".to_string(),
        "-global".to_string(),
        "isa-debugcon.iobase=0x402".to_string(),
        "-L".to_string(),
        "/usr/local/share/qemu_smm/".to_string(),
        "-nographic".to_string(),
    ]
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