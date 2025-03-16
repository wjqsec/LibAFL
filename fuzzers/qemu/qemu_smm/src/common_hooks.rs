use libafl_bolts::AsSliceMut;
use libafl_qemu::{GuestAddr, GuestReg, CPU,Regs,Qemu};

use log::*;

use crate::exit_qemu::ExitProcessType;
use crate::{exit_elegantly, stream_input::*,SmmQemuExit};
use std::cell::UnsafeCell;
use std::process::exit;
use once_cell::sync::Lazy;
use std::sync::{Arc, Mutex};
use std::vec::*;
use std::slice;
use std::cmp::min;
use std::collections::{HashSet};
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, NasmFormatter};
use uuid::*;
use crate::smi_info::*;
use crate::coverage::*;
use crate::smm_fuzz_qemu_cmds::*;

const SMRAM_START : u64 = 0x4800000;
const SMRAM_END : u64 = 0x8000000;
const UEFI_RAM_END : u64 = 0x100000000;
pub static mut IN_FUZZ : bool = false;

pub static mut IN_SMI : bool = false;

pub static mut GLOB_INPUT : *mut StreamInputs = std::ptr::null_mut() as *mut StreamInputs;

static mut NEXT_EXIT : Option<SmmQemuExit> = None;  // use this variblae to prevent memory leak

static mut DUMMY_MEMORY_ADDR : u64 = 0;
static mut DUMMY_MEMORY_SIZE : u64 = 0;
static mut DUMMY_MEMORY_HOST_PTR : *mut u64 = 0 as *mut u64;

static mut SMI_SELECT_BUFFER_ADDR : u64 = 0;
static mut SMI_SELECT_BUFFER_SIZE : u64 = 0;
static mut SMI_SELECT_BUFFER_HOST_PTR : *mut u8 = 0 as *mut u8;

static mut COMMBUF_ADDR : u64 = 0;
static mut COMMBUF_SIZE : u64 = 0;
static mut COMMBUF_ACTUAL_SIZE : u64 = 0;
static mut COMMBUF_HOST_PTR : *mut u8 = 0 as *mut u8;

static mut HOB_ADDR : u64 = 0;
static mut HOB_SIZE : u64 = 0;

static mut DXE_BUFFER_ADDR : u64 = 0;
static mut DXE_BUFFER_SIZE : u64 = 0;

pub static mut REDZONE_BUFFER_AADR : u64 = 0;

static mut MISSING_PROTOCOLS: Lazy<HashSet<Uuid>> = Lazy::new(|| {
    HashSet::new()
});


static mut SMM_MIGHT_VUL : bool = false;

pub fn reset_smm_might_vul() {
    unsafe {
        SMM_MIGHT_VUL = false;
    }
}
pub fn smm_might_vul() -> bool {
    unsafe {
        SMM_MIGHT_VUL
    }
}

static mut EXEC_COUNT : u64 = 0;
pub fn get_exec_count() -> u64 {
    unsafe {
        EXEC_COUNT
    }
}
pub fn set_exec_count(val :u64) {
    unsafe {
        EXEC_COUNT = val;
    }
}


pub fn wrmsr_common(in_ecx: u32, in_eax: *mut u32, in_edx: *mut u32)
{
    unsafe {
        let eax_info = *in_eax;
        let edx_info = *in_edx;
        debug!("[wrmsr] {in_ecx:#x} {eax_info:#x} {edx_info:#x}");
    }
}
fn cpuid_common(in_eax: u32, out_eax: *mut u32,out_ebx: *mut u32, out_ecx: *mut u32, out_edx: *mut u32, fuzz_input : &mut StreamInputs, cpu : CPU)
{
    match fuzz_input.get_cpuid_fuzz_data() {
        Ok(fuzz_input_ptr) => { 
            unsafe {
                out_eax.copy_from(fuzz_input_ptr as *const u32, 1); 
                out_ebx.copy_from((fuzz_input_ptr as *const u32).offset(1), 1);
                out_ecx.copy_from((fuzz_input_ptr as *const u32).offset(2), 1);
                out_edx.copy_from((fuzz_input_ptr as *const u32).offset(3), 1);
            }
        },
        Err(io_err) => {    
            match io_err {
                StreamError::StreamNotFound(id) => {
                    fuzz_input.generate_init_stream(id);
                    match fuzz_input.get_cpuid_fuzz_data() {
                        Ok(fuzz_input_ptr) => { 
                            unsafe {
                                out_eax.copy_from(fuzz_input_ptr as *const u32, 1); 
                                out_ebx.copy_from((fuzz_input_ptr as *const u32).offset(1), 1);
                                out_ecx.copy_from((fuzz_input_ptr as *const u32).offset(2), 1);
                                out_edx.copy_from((fuzz_input_ptr as *const u32).offset(3), 1);
                            }
                        },
                        _ => {    
                            error!("cpuid stream generate error");
                            exit_elegantly(ExitProcessType::Error);
                        }
                    }
                },
                StreamError::StreamOutof(id, need_len) => {
                    let append_data = fuzz_input.append_temp_stream(id, need_len);
                    unsafe {
                        out_eax.copy_from(append_data.as_ptr() as *const u32, 1); 
                        out_ebx.copy_from((append_data.as_ptr() as *const u32).offset(1), 1);
                        out_ecx.copy_from((append_data.as_ptr() as *const u32).offset(2), 1);
                        out_edx.copy_from((append_data.as_ptr() as *const u32).offset(3), 1);
                        NEXT_EXIT = Some(SmmQemuExit::StreamOutof);
                    }
                },
                _ => {
                    error!("cpuid stream get error");
                    exit_elegantly(ExitProcessType::Error);
                }
            }
        }
    }
}
pub fn cpuid_init_fuzz_phase(in_eax: u32, out_eax: *mut u32,out_ebx: *mut u32, out_ecx: *mut u32, out_edx: *mut u32, fuzz_input : &mut StreamInputs, cpu : CPU)
{
    unsafe {
        if IN_FUZZ == false {
            return;
        }
    }
    cpuid_common(in_eax, out_eax, out_ebx, out_ecx, out_edx, fuzz_input, cpu);
}

fn post_io_read_common(pc : u64, io_addr : GuestAddr, size : usize, data : *mut u8, 
                       fuzz_input : &mut StreamInputs, cpu : CPU)
{   

    match fuzz_input.get_io_fuzz_data(pc, io_addr, size as u64) {
        Ok(fuzz_input_ptr) => { 
            unsafe {data.copy_from(fuzz_input_ptr, size as usize);}
        },
        Err(io_err) => {    
            match io_err {
                StreamError::StreamNotFound(id) => {
                    fuzz_input.generate_init_stream(id);
                    match fuzz_input.get_io_fuzz_data(pc, io_addr, size as u64) {
                        Ok(fuzz_input_ptr) => { 
                            unsafe {data.copy_from(fuzz_input_ptr, size as usize);}
                        },
                        _ => {    
                            error!("io stream generate error");
                            exit_elegantly(ExitProcessType::Error);
                        }
                    }
                },
                StreamError::StreamOutof(id, need_len) => {
                    let append_data = fuzz_input.append_temp_stream(id, need_len);
                    unsafe {
                        data.copy_from(append_data.as_ptr(), need_len);
                        NEXT_EXIT = Some(SmmQemuExit::StreamOutof);
                    }
                },
                _ => {
                    error!("io stream get error");
                    exit_elegantly(ExitProcessType::Error);
                }
            }
        }
    }


    let value = match size {
        1 => unsafe { *( data as *mut u8) as u64},
        2 => unsafe { *( data as *mut u16) as u64},
        4 => unsafe { *( data as *mut u32) as u64},
        8 => unsafe { *( data as *mut u64) as u64},
        _ => {
            error! ("post_io_read size error {:#x}!",size);
            exit_elegantly(ExitProcessType::Error);
            0
        },
        
    };

    debug!("[io] post_io_read pc:{} io_addr:{io_addr:#x} size:{size:#x} value:{value:#x}",get_readable_addr(pc));

}

pub fn post_io_read_init_fuzz_phase(base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, io_err : u32, 
    fuzz_input : &mut StreamInputs, cpu : CPU)
{
    let pc : GuestReg = cpu.read_reg(Regs::Pc).unwrap();
    let addr = base + offset;
    unsafe {
        if IN_FUZZ == false {
            return;
        }
    }
    post_io_read_common(pc, addr, size, data, fuzz_input, cpu);
}
pub fn post_io_read_smm_fuzz_phase(base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, io_err : u32, 
    fuzz_input : &mut StreamInputs, cpu : CPU)
{
    let pc : GuestReg = cpu.read_reg(Regs::Pc).unwrap();
    let addr = base + offset;
    unsafe {
        if IN_FUZZ == false || IN_SMI == false {
            return;
        }
    }
    post_io_read_common(pc, addr, size, data, fuzz_input, cpu);
}

fn pre_io_write_common(base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : *mut bool, cpu : CPU)
{
    let pc : GuestReg = cpu.read_reg(Regs::Pc).unwrap();
    let value = match size {
        1 => unsafe { *( data as *mut u8) as u64},
        2 => unsafe { *( data as *mut u16) as u64},
        4 => unsafe { *( data as *mut u32) as u64},
        8 => unsafe { *( data as *mut u64) as u64},
        _ => {
            error! ("pre_io_write size error {:#x}!",size);
            exit_elegantly(ExitProcessType::Error);
            0
        },
    };
    let addr = base + offset;
    debug!("[io] pre_io_write pc:{} io_addr:{addr:#x} size:{size:#x} value:{value:#x}",get_readable_addr(pc));
}

pub fn pre_io_write_init_fuzz_phase(base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : *mut bool, cpu : CPU)
{
    let pc : GuestReg = cpu.read_reg(Regs::Pc).unwrap();
    let addr = base + offset;
    unsafe {
        if IN_FUZZ == false {
            return;
        }
        if addr != 0x402 {
            *handled = true;
            return;
        }
        
    }
    pre_io_write_common(base, offset, size, data, handled, cpu);
}
pub fn pre_io_write_smm_fuzz_phase(base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : *mut bool, cpu : CPU)
{
    let addr = base + offset;
    unsafe {
        if IN_FUZZ == false || IN_SMI == false {
            return;
        }
        if addr != 0x402 {
            *handled = true;
            return;
        }
    }
    pre_io_write_common(base, offset, size, data, handled, cpu);
}

fn pre_memrw_common(pc : GuestReg, addr : GuestAddr, size : u64 , out_addr : *mut GuestAddr, rw : u32, val : u128, fuzz_input : &mut StreamInputs, cpu : CPU, consistent_access : bool)
{
    match rw { // read
        0 => {
            match fuzz_input.get_dram_fuzz_data(addr, size, consistent_access) {
                Ok(data) => { 
                    unsafe {
                        *DUMMY_MEMORY_HOST_PTR = data;
                        *out_addr = DUMMY_MEMORY_ADDR;
                    }
                },
                Err(io_err) => {    
                    match io_err {
                        StreamError::StreamNotFound(id) => {
                            fuzz_input.generate_init_stream(id);
                            match fuzz_input.get_dram_fuzz_data(addr,size, consistent_access) {
                                Ok(data) => { 
                                    unsafe { 
                                        *DUMMY_MEMORY_HOST_PTR = data;
                                        *out_addr = DUMMY_MEMORY_ADDR;
                                    }
                                },
                                Err(io_err) => {    
                                    error!("dram fuzz data generate error");
                                    exit_elegantly(ExitProcessType::Error);
                                }
                            }
                        },
                        StreamError::StreamOutof(id, need_len) => {
                            let append_data = fuzz_input.append_temp_stream(id, need_len);
                            if consistent_access {
                                fuzz_input.init_dram_value(addr, &append_data);
                                match fuzz_input.get_dram_fuzz_data(addr, size, consistent_access) {
                                    Ok(data) => { 
                                        unsafe { 
                                            *DUMMY_MEMORY_HOST_PTR = data;
                                            *out_addr = DUMMY_MEMORY_ADDR;
                                            NEXT_EXIT = Some(SmmQemuExit::StreamOutof);
                                        }
                                    },
                                    _ => {
                                        error!("dram fuzz data append error");
                                        exit_elegantly(ExitProcessType::Error);
                                    },
                                }
                            } else {
                                unsafe {
                                    (DUMMY_MEMORY_HOST_PTR as *mut u8).copy_from(append_data.as_ptr(), append_data.len());
                                    *out_addr = DUMMY_MEMORY_ADDR;
                                }
                            }
                            
                        },
                        _ => {
                            error!("dram fuzz data get error");
                            exit_elegantly(ExitProcessType::Error);
                        },
                    }
                }
            }
        },
        1 => {
            unsafe {
                *out_addr = DUMMY_MEMORY_ADDR;
                // fuzz_input.set_dram_value(addr, size, &val.to_le_bytes());
            }
        },
        2 => {

        },
        3 => {

        },
        4 => {

        },
        _ => {

        },
    }
    

}

pub static mut MEM_SHOULD_FUZZ_SWITCH : bool = false;

pub fn set_fuzz_mem_switch(fuzz_input : &mut StreamInputs) {
    unsafe {MEM_SHOULD_FUZZ_SWITCH = false;}
    match fuzz_input.get_fuzz_mem_switch_fuzz_data() {
        Ok(data) => { 
            unsafe { 
                if data & 1 == 1 {
                    unsafe { MEM_SHOULD_FUZZ_SWITCH = true; }
                }
            }
        },
        Err(io_err) => {    
            match io_err {
                StreamError::StreamNotFound(id) => {
                    fuzz_input.generate_init_stream(id);
                    match fuzz_input.get_fuzz_mem_switch_fuzz_data() {
                        Ok(data) => { 
                            if data & 1 == 1 {
                                unsafe { MEM_SHOULD_FUZZ_SWITCH = true; }
                            }
                        },
                        _ => {    
                            error!("fuzz mem switch data generate error");
                            exit_elegantly(ExitProcessType::Error);
                        }
                    }
                },
                StreamError::StreamOutof(id, need_len) => {
                    let append_data = fuzz_input.append_temp_stream(id, need_len);
                    if append_data[0] & 1 == 1 {
                        unsafe { MEM_SHOULD_FUZZ_SWITCH = true; }
                    }
                },
                _ => {
                    error!("fuzz mem switch data get error");
                    exit_elegantly(ExitProcessType::Error);
                }
            }
        }
    }
}
pub fn pre_memrw_init_fuzz_phase(pc : GuestReg, addr : GuestAddr, size : u64 , out_addr : *mut GuestAddr, rw : u32, val : u128, fuzz_input : &mut StreamInputs, cpu : CPU)
{
    unsafe {
        if IN_FUZZ == false {
            return;
        }
        if addr < UEFI_RAM_END {  
            if !(
                addr >= HOB_ADDR && addr < (HOB_ADDR + 2) 
                || addr >= ( HOB_ADDR + 8 ) && addr < (HOB_ADDR + HOB_SIZE) 
                || addr >= DXE_BUFFER_ADDR && addr < (DXE_BUFFER_ADDR + DXE_BUFFER_SIZE)
            ) {
                return;
            }  
        }
    }
    pre_memrw_common(pc, addr, size, out_addr, rw, val, fuzz_input, cpu, false);
}
pub fn pre_memrw_smm_fuzz_phase(pc : GuestReg, addr : GuestAddr, size : u64 , out_addr : *mut GuestAddr, rw : u32, val : u128, fuzz_input : &mut StreamInputs, cpu : CPU) -> bool
{
    unsafe {
        if IN_FUZZ == false || IN_SMI == false {
            return false;
        }
    }
    if addr >= SMRAM_START && addr < SMRAM_END { // inside sram
        return false;
    }
    if addr >= unsafe {COMMBUF_ADDR} && addr < unsafe {COMMBUF_ADDR + COMMBUF_ACTUAL_SIZE} {  //outside comm buffer
        return false;
    }
    if addr > UEFI_RAM_END && rw == 1 {
        unsafe {
            SMM_MIGHT_VUL = true;
        }
    }
    pre_memrw_common(pc, addr, size, out_addr, rw, val, fuzz_input, cpu, false);
    return true;
}
pub fn pre_memrw_smm_fuzz_phase_debug(pc : GuestReg, addr : GuestAddr, size : u64 , out_addr : *mut GuestAddr, rw : u32, val : u128, fuzz_input : &mut StreamInputs, cpu : CPU)
{
    let pc = cpu.read_reg(Regs::Rip).unwrap();
    let fuzz_value_used = pre_memrw_smm_fuzz_phase(pc, addr, size, out_addr, rw, val, fuzz_input, cpu);
    if unsafe {IN_SMI == true} {
        if rw == 0 {
            if fuzz_value_used {
                debug!("[mem] pc:{} {} addr:{:#x} size:{} value:{:#x}",get_readable_addr(pc), "read", addr, size, unsafe {*DUMMY_MEMORY_HOST_PTR});
            } else {
                let mut mem_data : [u8; 8] = [0 ; 8];
                unsafe {
                    cpu.read_mem(addr,&mut mem_data);
                }
                debug!("[mem] pc:{} {} addr:{:#x} size:{} value:{:#x}",get_readable_addr(pc), "read", addr, size, u64::from_le_bytes(mem_data));
            }
            
        } else {
            debug!("[mem] pc:{} {} addr:{:#x} size:{} value:{:#x}",get_readable_addr(pc), "write", addr, size, val);
        }
    }
}

fn rdmsr_common(in_ecx: u32, out_eax: *mut u32, out_edx: *mut u32,fuzz_input : &mut StreamInputs)
{
    match fuzz_input.get_msr_fuzz_data() {
        Ok((fuzz_input_ptr)) => { 
            unsafe { 
                out_eax.copy_from(fuzz_input_ptr as *const u32, 1); 
                out_edx.copy_from((fuzz_input_ptr as *const u32).offset(1), 1);
            }
        },
        Err(io_err) => {    
            match io_err {
                StreamError::StreamNotFound(id) => {
                    fuzz_input.generate_init_stream(id);
                    match fuzz_input.get_msr_fuzz_data() {
                        Ok((fuzz_input_ptr)) => { 
                            unsafe { 
                                out_eax.copy_from(fuzz_input_ptr as *const u32, 1); 
                                out_edx.copy_from((fuzz_input_ptr as *const u32).offset(1), 1);
                            }
                        },
                        _ => {    
                            error!("msr fuzz data generate error");
                            exit_elegantly(ExitProcessType::Error);
                        }
                    }
                },
                StreamError::StreamOutof(id, need_len) => {
                    unsafe {
                        let append_data = fuzz_input.append_temp_stream(id, need_len);
                        out_eax.copy_from(append_data.as_ptr() as *const u32, 1); 
                        out_edx.copy_from((append_data.as_ptr() as *const u32).offset(1), 1);
                        NEXT_EXIT = Some(SmmQemuExit::StreamOutof);
                    }
                }
                _ => {
                    error!("msr fuzz data get error");
                    exit_elegantly(ExitProcessType::Error);
                }
            }
        }
    }

    unsafe {
        let eax_info = *out_eax;
        let edx_info = *out_edx;
        debug!("[rdmsr] {in_ecx:#x} {eax_info:#x} {edx_info:#x}");
    }
}
pub fn rdmsr_init_fuzz_phase(in_ecx: u32, out_eax: *mut u32, out_edx: *mut u32,fuzz_input : &mut StreamInputs) 
{
    unsafe {
        if IN_FUZZ == false {
            return;
        }
    }
    rdmsr_common(in_ecx, out_eax, out_edx, fuzz_input);
}
pub fn rdmsr_smm_fuzz_phase(in_ecx: u32, out_eax: *mut u32, out_edx: *mut u32,fuzz_input : &mut StreamInputs) 
{
    unsafe {
        if IN_FUZZ == false || IN_SMI == false {
            return;
        }
    }
    rdmsr_common(in_ecx, out_eax, out_edx, fuzz_input);
}

static mut SKIP_CURRENT_MODULE : bool = false;
pub fn skip() {
    warn!("unable to process, skip");
    unsafe {
        SKIP_CURRENT_MODULE = true;
    }
}
pub fn unskip() {
    unsafe {
        SKIP_CURRENT_MODULE = false;
    }
}
pub fn missing_smm_protocols_empty() -> bool {
    unsafe {
        MISSING_PROTOCOLS.is_empty()
    }
}
pub fn backdoor_common(fuzz_input : &mut StreamInputs, cpu : CPU)
{
    let pc : GuestReg = cpu.read_reg(Regs::Pc).unwrap();
    let cmd : GuestReg = cpu.read_reg(Regs::Rax).unwrap();
    let arg1 : GuestReg = cpu.read_reg(Regs::Rdi).unwrap();
    let arg2 : GuestReg = cpu.read_reg(Regs::Rsi).unwrap();
    let arg3 : GuestReg = cpu.read_reg(Regs::Rdx).unwrap();
    let mut ret : u64 = 0;
    match cmd {
        LIBAFL_QEMU_COMMAND_SMM_REPORT_DUMMY_MEM => {
            unsafe {
                DUMMY_MEMORY_ADDR = arg1;
                DUMMY_MEMORY_SIZE = arg2;
                let dummy_memory_phy_addr = cpu.get_phys_addr_with_offset(DUMMY_MEMORY_ADDR).unwrap();
                let dummy_memory_host_addr = cpu.get_host_addr(dummy_memory_phy_addr);
                DUMMY_MEMORY_HOST_PTR = dummy_memory_host_addr as *mut u64;
                debug!("[backdoor] dummy memory info {:#x} {:#x} {:?}",DUMMY_MEMORY_ADDR,DUMMY_MEMORY_SIZE,DUMMY_MEMORY_HOST_PTR);
            }
        },
        LIBAFL_QEMU_COMMAND_SMM_REPORT_SMI_SELECT_INFO => {
            unsafe {
                SMI_SELECT_BUFFER_ADDR = arg1;
                SMI_SELECT_BUFFER_SIZE = arg2;
                let smi_select_buffer_phy_addr = cpu.get_phys_addr_with_offset(SMI_SELECT_BUFFER_ADDR).unwrap();
                let smi_select_buffer_host_addr = cpu.get_host_addr(smi_select_buffer_phy_addr);
                SMI_SELECT_BUFFER_HOST_PTR = smi_select_buffer_host_addr;
                debug!("[backdoor] smi select buffer {:#x} {:#x} {:#x} {:?}",SMI_SELECT_BUFFER_ADDR, SMI_SELECT_BUFFER_SIZE, smi_select_buffer_phy_addr, SMI_SELECT_BUFFER_HOST_PTR);
            }
        },
        LIBAFL_QEMU_COMMAND_SMM_REPORT_COMMBUF_INFO => {
            unsafe {
                COMMBUF_ADDR = arg1;
                COMMBUF_SIZE = arg2;
                let commbuf_phy_addr = cpu.get_phys_addr_with_offset(COMMBUF_ADDR).unwrap();
                let commbuf_host_addr = cpu.get_host_addr(commbuf_phy_addr);
                COMMBUF_HOST_PTR = commbuf_host_addr;
                debug!("[backdoor] comm buffer {:#x} {:#x} {:#x} {:?}",COMMBUF_ADDR, COMMBUF_SIZE, commbuf_phy_addr, COMMBUF_HOST_PTR);
            }
        },
        LIBAFL_QEMU_COMMAND_SMM_GET_SMI_SELECT_FUZZ_DATA => {
            let mut current_group_index = 0;
            match fuzz_input.get_smi_group_index_fuzz_data() {
                Ok((group_index)) => { 
                    current_group_index = group_index;
                },
                Err(io_err) => {    
                    error!("smi group index data get error");
                    exit_elegantly(ExitProcessType::Error);
                }
            }   
            match fuzz_input.get_smi_select_info_fuzz_data() {
                Ok((fuzz_input_ptr, len)) => { 
                    unsafe { 
                        for i in 0..len {
                            let current_addr = unsafe { SMI_SELECT_BUFFER_HOST_PTR.add(i) };
                            let random_index = unsafe { *fuzz_input_ptr.add(i) };
                            if let Some(index) = get_smi_by_random_group_index(current_group_index, random_index) {
                                *current_addr = index;
                            } else {
                                error!("smi select info error");
                                exit_elegantly(ExitProcessType::Error);
                            }
                        }
                    }
                    ret = len as u64;
                },
                Err(io_err) => {    
                    match io_err {
                        StreamError::StreamNotFound(id) => {
                            fuzz_input.generate_init_stream(id);
                            match fuzz_input.get_smi_select_info_fuzz_data() {
                                Ok((fuzz_input_ptr, len)) => { 
                                    unsafe { 
                                        for i in 0..len {
                                            let current_addr = unsafe { SMI_SELECT_BUFFER_HOST_PTR.add(i) };
                                            let random_index = unsafe { *fuzz_input_ptr.add(i) };
                                            if let Some(index) = get_smi_by_random_group_index(current_group_index, random_index) {
                                                *current_addr = index;
                                            } else {
                                                error!("smi select info error");
                                                exit_elegantly(ExitProcessType::Error);
                                            }
                                        }
                                    }
                                    ret = len as u64;
                                },
                                _ => {    
                                    error!("smi select info generate error");
                                    exit_elegantly(ExitProcessType::Error);
                                },
                            }
                        },
                        _ => {
                            error!("smi select info get error");
                            exit_elegantly(ExitProcessType::Error);
                        },
                    }
                }
            }
        },
        LIBAFL_QEMU_COMMAND_SMM_GET_COMMBUF_FUZZ_DATA => {
            if unsafe {IN_FUZZ} {
                let smi_index = arg1;
                let smi_invoke_times = arg2;
                match fuzz_input.get_commbuf_fuzz_data(smi_index, smi_invoke_times) {
                    Ok((fuzz_input_ptr,  claimed_len, actual_len)) => { 
                        let written_len = min(unsafe {COMMBUF_SIZE} as usize, actual_len);
                        unsafe { 
                            COMMBUF_HOST_PTR.copy_from(fuzz_input_ptr, written_len); 
                            COMMBUF_ACTUAL_SIZE = written_len as u64;
                        }
                        ret = claimed_len as u64;
                    },
                    Err(io_err) => {    
                        match io_err {
                            StreamError::StreamNotFound(id) => {
                                fuzz_input.generate_init_stream(id);
                                match fuzz_input.get_commbuf_fuzz_data(smi_index, smi_invoke_times) {
                                    Ok((fuzz_input_ptr, claimed_len, actual_len)) => { 
                                        let written_len = min(unsafe {COMMBUF_SIZE} as usize, actual_len);
                                        unsafe { 
                                            COMMBUF_HOST_PTR.copy_from(fuzz_input_ptr, written_len); 
                                            COMMBUF_ACTUAL_SIZE = written_len as u64;
                                        }
                                        ret = claimed_len as u64;
                                    },
                                    _ => {    
                                        error!("comm buffer generate error");
                                        exit_elegantly(ExitProcessType::Error);
                                    }
                                }
                            },
                            _ => {
                                ret = 0;
                            },
                        }
                    }
                }
            } else {
                ret = 0;
            }
        },
        LIBAFL_QEMU_COMMAND_SMM_GET_PCD_FUZZ_DATA => {
            let len = arg1;
            let addr = arg2;
            if unsafe { IN_FUZZ } {
                ret = 1;
                if len > 0 && len <= 8 {
                    match fuzz_input.get_pcd_fuzz_data(len) {
                        Ok((fuzz_input_ptr)) => { 
                            unsafe {
                                cpu.write_mem(addr, slice::from_raw_parts(fuzz_input_ptr, len as usize));
                            }
                        },
                        Err(io_err) => {    
                            match io_err {
                                StreamError::StreamNotFound(id) => {
                                    fuzz_input.generate_init_stream(id);
                                    match fuzz_input.get_pcd_fuzz_data(len) {
                                        Ok((fuzz_input_ptr)) => { 
                                            unsafe {
                                                cpu.write_mem(addr, slice::from_raw_parts(fuzz_input_ptr, len as usize));
                                            }
                                        },
                                        _ => {    
                                            error!("pcd data generate error");
                                            exit_elegantly(ExitProcessType::Error);
                                        }
                                    }
                                },
                                StreamError::StreamOutof(id, need_len) => {
                                    let append_data = fuzz_input.append_temp_stream(id, need_len);
                                    unsafe {
                                        cpu.write_mem(addr, append_data.as_slice());
                                    }
                                    
                                },
                                _ => {
                                    error!("pcd data get error");
                                    exit_elegantly(ExitProcessType::Error);
                                },
                            }
                        }
                    }
                } else if len == 0 {
                    let ret_pcd_ptr : u64 = 0xb000000000000000;  
                    unsafe {
                        cpu.write_mem(addr, &ret_pcd_ptr.to_le_bytes());
                    }
                }
            } else {
                ret = 0;
            }
        },
        LIBAFL_QEMU_COMMAND_SMM_REPORT_HOB_MEM => {
            unsafe {
                HOB_ADDR = arg1;
                HOB_SIZE = arg2;
            }
        },
        LIBAFL_QEMU_COMMAND_SMM_SMI_ENTER => {
            unsafe {
                IN_SMI = true;
            }

            let guid_addr = arg1;
            let target_addr = arg2;
            if guid_addr == 0 {
                debug!("[backdoor] SMI enter root handler {}", get_readable_addr(target_addr));
            } else {
                let mut guid_buf : [u8; 16] = [0 ; 16];
                unsafe {
                    cpu.read_mem(guid_addr,&mut guid_buf);
                }
                let handler_guid = Uuid::from_bytes_le(guid_buf);
                debug!("[backdoor] SMI enter {} {}", handler_guid.to_string(), get_readable_addr(target_addr));
            }
            
            
        },
        LIBAFL_QEMU_COMMAND_SMM_SMI_EXIT => {
            unsafe {
                IN_SMI = false;
            }
            debug!("[backdoor] SMI exit");
        },
        LIBAFL_QEMU_COMMAND_SMM_GET_VARIABLE_FUZZ_DATA => {
            let addr = arg1;
            let var_size = arg2;
            if unsafe { IN_FUZZ } {
                ret = 1;
                match fuzz_input.get_variable_fuzz_data(var_size) {
                    Ok((fuzz_input_ptr)) => { 
                        unsafe {
                            cpu.write_mem(addr, slice::from_raw_parts(fuzz_input_ptr, var_size as usize));
                        }
                    },
                    Err(io_err) => {    
                        match io_err {
                            StreamError::StreamNotFound(id) => {
                                fuzz_input.generate_init_stream(id);
                                match fuzz_input.get_variable_fuzz_data(var_size) {
                                    Ok((fuzz_input_ptr)) => { 
                                        unsafe {
                                            cpu.write_mem(addr, slice::from_raw_parts(fuzz_input_ptr, var_size as usize));
                                        }
                                    },
                                    _ => {    
                                        error!("variable data generate error, request too much variable data {:}",var_size);
                                        exit_elegantly(ExitProcessType::Error);
                                    }
                                }
                            },
                            StreamError::StreamOutof(id, need_len) => {
                                let append_data = fuzz_input.append_temp_stream(id, need_len);
                                unsafe {
                                    cpu.write_mem(addr, append_data.as_slice());
                                }
                            },
                            _ => {
                                error!("variable data get error");
                                exit_elegantly(ExitProcessType::Error);
                            },
                        }
                    }
                }   
            } else {
                ret = 0;
            }
        },
        LIBAFL_QEMU_COMMAND_SMM_GET_SAVE_REGISTER_FUZZ_DATA => {
            let addr = arg1;
            let reg_size = arg2;
            if unsafe { IN_SMI && IN_FUZZ } {
                ret = 1;
                if reg_size != 0 {
                    match fuzz_input.get_save_register_fuzz_data(reg_size) {
                        Ok((fuzz_input_ptr)) => { 
                            unsafe {
                                cpu.write_mem(addr, slice::from_raw_parts(fuzz_input_ptr, reg_size as usize));
                            }
                        },
                        Err(io_err) => {    
                            match io_err {
                                StreamError::StreamNotFound(id) => {
                                    fuzz_input.generate_init_stream(id);
                                    match fuzz_input.get_save_register_fuzz_data(reg_size) {
                                        Ok((fuzz_input_ptr)) => { 
                                            unsafe {
                                                cpu.write_mem(addr, slice::from_raw_parts(fuzz_input_ptr, reg_size as usize));
                                            }
                                        },
                                        _ => {    
                                            error!("save register generate error, request too much variable data {:}",reg_size);
                                            exit_elegantly(ExitProcessType::Error);
                                        }
                                    }
                                },
                                StreamError::StreamOutof(id, need_len) => {
                                    let append_data = fuzz_input.append_temp_stream(id, need_len);
                                    unsafe {
                                        cpu.write_mem(addr, append_data.as_slice());
                                    }
                                },
                                _ => {
                                    error!("save register data get error");
                                    exit_elegantly(ExitProcessType::Error);
                                },
                            }
                        }
                    } 
                }
            } else {
                ret = 0;
            }
        },
        LIBAFL_QEMU_COMMAND_SMM_GET_SMI_GROUP_INDEX_FUZZ_DATA => {
            
        },
        LIBAFL_QEMU_COMMAND_SMM_ASK_SKIP_MODULE => {
            unsafe {
                if SKIP_CURRENT_MODULE {
                    ret = 1;
                } else {
                    ret = 0;
                }
            }
        },
        LIBAFL_QEMU_COMMAND_SMM_REPORT_SMM_MODULE_INFO => {
            let addr = arg1;
            let start_addr = arg2;
            let end_addr = arg3;
            let mut guid_buf : [u8; 16] = [0 ; 16];
            unsafe {
                cpu.read_mem(addr,&mut guid_buf);
            }
            let module_guid = Uuid::from_bytes_le(guid_buf);
            module_range(&module_guid, start_addr, end_addr);
            unsafe {
                MISSING_PROTOCOLS.clear();
            }
            info!("[Module] {} {:#x}-{:#x}", module_guid.to_string(), start_addr, end_addr);
        },
        LIBAFL_QEMU_COMMAND_SMM_REPORT_SMI_INFO => {
            let index = arg1;
            let addr = arg2;
            let mut guid_buf : [u8; 16] = [0 ; 16];
            unsafe {
                cpu.read_mem(addr,&mut guid_buf);
            }
            let smi_guid = Uuid::from_bytes_le(guid_buf);
            info!("[SMI] {} {}",index, smi_guid.to_string());
        },
        LIBAFL_QEMU_COMMAND_SMM_REPORT_SMM_FUZZ_GROUP => {
            let group = arg1 as u8;
            let smi_index = arg2 as u8;
            add_smi_group_info(group, smi_index);
        },
        LIBAFL_QEMU_COMMAND_SMM_REPORT_SKIP_MODULE_INFO => {
            let addr = arg1;
            let mut guid_buf : [u8; 16] = [0 ; 16];
            unsafe {
                cpu.read_mem(addr,&mut guid_buf);
            }
            let module_guid = Uuid::from_bytes_le(guid_buf);
            info!("[SKIP] {}",module_guid.to_string());
        },
        LIBAFL_QEMU_COMMAND_SMM_REPORT_UNLOAD_MODULE_INFO => {
            let addr = arg1;
            let mut guid_buf : [u8; 16] = [0 ; 16];
            unsafe {
                cpu.read_mem(addr,&mut guid_buf);
            }
            let module_guid = Uuid::from_bytes_le(guid_buf);
            info!("[UNLOAD] {}",module_guid.to_string());
        },
        LIBAFL_QEMU_COMMAND_SMM_HELP_COPY => {
            let dst = arg1;
            let src = arg2;
            let size = arg3;
            unsafe {
                let mut buf : Vec<u8> = vec![0; size as usize];
                cpu.read_mem(src, buf.as_slice_mut());
                cpu.write_mem(dst, buf.as_slice());
            }
        },
        LIBAFL_QEMU_COMMAND_SMM_REPORT_MISSING_PROTOCOL => {
            let direcction = arg1;
            let addr = arg2;
            if direcction == REPORT_TO_FUZZER {
                let mut guid_buf : [u8; 16] = [0 ; 16];
                unsafe {
                    cpu.read_mem(addr,&mut guid_buf);
                    let protocol_guid = Uuid::from_bytes_le(guid_buf);
                    MISSING_PROTOCOLS.insert(protocol_guid);
                    
                }
            } else {
                let mut i = 0;
                for protocol in unsafe {MISSING_PROTOCOLS.iter()} {
                    let missing_protocol = protocol.to_bytes_le();
                    unsafe {
                        cpu.write_mem(addr + i * 16, &missing_protocol);
                    }
                    i += 1;
                }
                ret = unsafe {MISSING_PROTOCOLS.len()} as u64;
            }
        },
        LIBAFL_QEMU_COMMAND_SMM_REPORT_DXE_BUFFER => {
            unsafe {
                DXE_BUFFER_ADDR = arg1;
                DXE_BUFFER_SIZE = arg2;
                info!("[backdoor] DXE buffer {:#x} {:#x}",DXE_BUFFER_ADDR, DXE_BUFFER_SIZE);
            }
        },
        LIBAFL_QEMU_COMMAND_SMM_REPORT_REDZONE_BUFFER_ADDR => {
            unsafe {
                REDZONE_BUFFER_AADR = arg1;
            }
            info!("[backdoor] red zone buffer addr {:#x}",arg1);
        },
        _ => { 
            error!("[backdoor] backdoor wrong cmd {:}",cmd); 
            exit_elegantly(ExitProcessType::Error)
        },
    };
    cpu.write_reg(Regs::Rax,ret).unwrap();
}

static mut NUM_TIMEOUT_BBL : u64 = 0xffffffffff;
pub fn set_num_timeout_bbl(bbl : u64) {
    unsafe {
        NUM_TIMEOUT_BBL = bbl;
    }
}


pub fn bbl_common(cpu : CPU) {
    unsafe {
        match NEXT_EXIT {
            Some(SmmQemuExit::StreamNotFound) => {
                NEXT_EXIT = None;
                cpu.exit_stream_notfound();
            },
            Some(SmmQemuExit::StreamOutof) => {
                NEXT_EXIT = None;
                cpu.exit_stream_outof();
            }
            _ => {
            }
        } 
    }
    if get_exec_count() > unsafe { NUM_TIMEOUT_BBL } {
        cpu.exit_timeout();
    }
    set_exec_count(get_exec_count() + 1);
}

pub fn bbl_translate_init_fuzz_phase(cpu : CPU, pc : u64) {
    if pc > UEFI_RAM_END {
        cpu.exit_crash();
    }
}
pub fn bbl_translate_smm_fuzz_phase(cpu : CPU, pc : u64) {
    if unsafe {IN_SMI} {
        if pc > SMRAM_END || pc < SMRAM_START {
            cpu.exit_crash();
        }
    }
}


fn disassemble_raw_instruction(cpu : CPU, pc : u64) -> Vec<String> {
    let mut code = [0 as u8; 0x30];
    unsafe {
        cpu.read_mem(pc, &mut code);
    }
    let mut decoder =
        Decoder::with_ip(64, &code, pc, DecoderOptions::NONE);
    let mut formatter = NasmFormatter::new();
    formatter.options_mut().set_first_operand_char_index(10);
    let mut rets = Vec::new();
    let mut instruction = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);
        let mut output = String::new();
        formatter.format(&instruction, &mut output);
        rets.push(output);
        if iced_x86::FlowControl::Next != instruction.flow_control() {
            break;
        }
    }
    rets
}
pub fn bbl_debug(cpu : CPU) {
    let pc : GuestReg = cpu.read_reg(Regs::Pc).unwrap();
    // if unsafe {IN_SMI == true}
    {
        let rax : GuestReg = cpu.read_reg(Regs::Rax).unwrap();
        let rbx : GuestReg = cpu.read_reg(Regs::Rbx).unwrap();
        let rcx : GuestReg = cpu.read_reg(Regs::Rcx).unwrap();
        let rdx : GuestReg = cpu.read_reg(Regs::Rdx).unwrap();
        let rsi : GuestReg = cpu.read_reg(Regs::Rsi).unwrap();
        let rdi : GuestReg = cpu.read_reg(Regs::Rdi).unwrap();
        debug!("[bbl]-> {} pc:{} rax:{rax:#x} rbx:{rbx:#x} rcx:{rcx:#x} rdx:{rdx:#x} rsi:{rsi:#x} rdi:{rdi:#x}",get_exec_count(), get_readable_addr(pc));
        if !get_readable_addr(pc).contains(":") {
            let disas = disassemble_raw_instruction(cpu, pc);
            for ins in disas {
                debug!("[bbl]-> {}",ins);
            }
        }
    }
    bbl_exec_cov_record_common(pc);
    unsafe {
        match NEXT_EXIT {
            Some(SmmQemuExit::StreamNotFound) => {
                NEXT_EXIT = None;
                cpu.exit_stream_notfound();
            },
            Some(SmmQemuExit::StreamOutof) => {
                NEXT_EXIT = None;
                cpu.exit_stream_outof();
            }
            _ => {
            }
        } 
    }

    if get_exec_count() > unsafe { NUM_TIMEOUT_BBL } { 
        cpu.exit_timeout();
    }
    set_exec_count(get_exec_count() + 1);
}