use libafl_qemu::{GuestAddr, GuestReg, CPU,Regs,Qemu};

use log::*;

use crate::{exit_elegantly, stream_input::*,SmmQemuExit};
use std::cell::UnsafeCell;
use once_cell::sync::Lazy;
use std::sync::{Arc, Mutex};
use std::vec::*;
use std::slice;
use std::cmp::min;
use crate::smm_fuzz_qemu_cmds::*;

pub static mut IN_SMI_FUZZ_PHASE : bool = false;

pub static mut IN_FUZZ : bool = false;

pub static mut IN_SMI : bool = false;

pub static mut GLOB_INPUT : *mut StreamInputs = std::ptr::null_mut() as *mut StreamInputs;

static mut NEXT_EXIT : Option<SmmQemuExit> = None;  // use this variblae to prevent memory leak

pub static mut DUMMY_MEMORY_VIRT_ADDR : u64 = 0;
pub static mut DUMMY_MEMORY_HOST_PTR : *mut u64 = 0 as *mut u64;

static mut SMI_SELECT_BUFFER_ADDR : u64 = 0;
static mut SMI_SELECT_BUFFER_SIZE : u64 = 0;
static mut SMI_SELECT_BUFFER_HOST_PTR : *mut u8 = 0 as *mut u8;

static mut COMMBUF_ADDR : u64 = 0;
static mut COMMBUF_SIZE : u64 = 0;
static mut COMMBUF_HOST_PTR : *mut u8 = 0 as *mut u8;

static mut HOB_ADDR : u64 = 0;
static mut HOB_SIZE : u64 = 0;

static mut DEBUG_TRACE_ENABLE : bool = false;
pub fn enable_debug_trace() {
    unsafe {
        if !IN_SMI_FUZZ_PHASE {
            return;
        }
        DEBUG_TRACE_ENABLE = true;
    }
}
pub fn disable_debug_trace() {
    unsafe {
        if !IN_SMI_FUZZ_PHASE {
            return;
        }
        DEBUG_TRACE_ENABLE = false;
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

static mut CURRENT_MODULE_ADDR : u64 = 0;
static mut CURRENT_MODULE_END : u64 = 0;
pub fn set_current_module(addr : u64, end : u64) {
    unsafe {
        CURRENT_MODULE_ADDR = addr;
        CURRENT_MODULE_END = end;
    }
    info!("now processing module {:#x}-{:#x}",addr,end);
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
                            exit_elegantly();
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
                    exit_elegantly();
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
            exit_elegantly();
            0
        },
        
    };

    debug!("post_io_read {pc:#x} {io_addr:#x} {size:#x} {value:#x}");

}

pub fn post_io_read_init_fuzz_phase(base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, io_err : u32, 
    fuzz_input : &mut StreamInputs, cpu : CPU)
{
    let pc : GuestReg = cpu.read_reg(Regs::Pc).unwrap();
    let addr = base + offset;
    unsafe {
        if IN_FUZZ == false || io_err == 0 {
            return;
        }
        if pc < CURRENT_MODULE_ADDR || pc >= CURRENT_MODULE_END {
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
        // if io_err == 0 && addr != 0xb2 && addr != 0xb3 {
        //     return;
        // }
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
            exit_elegantly();
            0
        },
    };
    let addr = base + offset;
    debug!("pre_io_write {pc:#x} {addr:#x} {size:#x} {value:#x}");
}

pub fn pre_io_write_init_fuzz_phase(base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : *mut bool, cpu : CPU)
{
    let pc : GuestReg = cpu.read_reg(Regs::Pc).unwrap();
    let addr = base + offset;
    unsafe {
        if IN_FUZZ == false {
            return;
        }
        if pc < CURRENT_MODULE_ADDR || pc >= CURRENT_MODULE_END {
            return;
        }
    }
    pre_io_write_common(base, offset, size, data, handled, cpu);
}
pub fn pre_io_write_smm_fuzz_phase(base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : *mut bool, cpu : CPU)
{
    unsafe {
        if IN_FUZZ == false || IN_SMI == false {
            return;
        }
        *handled = true;
        return;
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
                        *out_addr = DUMMY_MEMORY_VIRT_ADDR;
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
                                        *out_addr = DUMMY_MEMORY_VIRT_ADDR;
                                    }
                                },
                                Err(io_err) => {    
                                    error!("dram fuzz data generate error");
                                    exit_elegantly();
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
                                            *out_addr = DUMMY_MEMORY_VIRT_ADDR;
                                            NEXT_EXIT = Some(SmmQemuExit::StreamOutof);
                                        }
                                    },
                                    _ => {
                                        error!("dram fuzz data append error");
                                        exit_elegantly();
                                    },
                                }
                            } else {
                                unsafe {
                                    (DUMMY_MEMORY_HOST_PTR as *mut u8).copy_from(append_data.as_ptr(), need_len);
                                    *out_addr = DUMMY_MEMORY_VIRT_ADDR;
                                }
                            }
                            
                        },
                        _ => {
                            error!("dram fuzz data get error");
                            exit_elegantly();
                        },
                    }
                }
            }
        },
        1 => {
            unsafe {
                *out_addr = DUMMY_MEMORY_VIRT_ADDR;
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
                            exit_elegantly();
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
                    exit_elegantly();
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
        if pc < CURRENT_MODULE_ADDR || pc >= CURRENT_MODULE_END {
            return;
        }
        if addr < 0xff000000 {  // higher than this, could be fuzzed
            if  addr < HOB_ADDR  || addr >= (HOB_ADDR + HOB_SIZE) { // non HOB accees not to mutate
                return;
            }
            if addr >= HOB_ADDR + 2 && addr < HOB_ADDR + 8 { // HOB length not to mutate
                return;
            }
        } else {
            if unsafe {!MEM_SHOULD_FUZZ_SWITCH} {
                return;
            }     
        }
    }
    pre_memrw_common(pc, addr, size, out_addr, rw, val, fuzz_input, cpu, false);
}
pub fn pre_memrw_smm_fuzz_phase(pc : GuestReg, addr : GuestAddr, size : u64 , out_addr : *mut GuestAddr, rw : u32, val : u128, fuzz_input : &mut StreamInputs, cpu : CPU)
{
    unsafe {
        if IN_FUZZ == false || IN_SMI == false {
            return;
        }
    }
    if addr >= 0x7000000 && addr < 0x8000000 { // inside sram
        return;
    }
    if addr >= unsafe {COMMBUF_ADDR} && addr < unsafe {COMMBUF_ADDR + COMMBUF_SIZE} {  //outside comm buffer
        return;
    }
    pre_memrw_common(pc, addr, size, out_addr, rw, val, fuzz_input, cpu, false);
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
                            exit_elegantly();
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
                    exit_elegantly();
                }
            }
        }
    }

    unsafe {
        let eax_info = *out_eax;
        let edx_info = *out_edx;
        debug!("rdmsr {in_ecx:#x} {eax_info:#x} {edx_info:#x}");
    }
}
pub fn rdmsr_init_fuzz_phase(in_ecx: u32, out_eax: *mut u32, out_edx: *mut u32,fuzz_input : &mut StreamInputs) 
{
    unsafe {
        if IN_FUZZ == false {
            return;
        }
    }
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
pub fn backdoor_common(fuzz_input : &mut StreamInputs, cpu : CPU)
{
    let pc : GuestReg = cpu.read_reg(Regs::Pc).unwrap();
    let cmd : GuestReg = cpu.read_reg(Regs::Rax).unwrap();
    let arg1 : GuestReg = cpu.read_reg(Regs::Rdi).unwrap();
    let arg2 : GuestReg = cpu.read_reg(Regs::Rsi).unwrap();
    let arg3 : GuestReg = cpu.read_reg(Regs::Rdx).unwrap();
    let mut ret : u64 = 0;
    debug!("backdoor_common {cmd} {arg1:#x} {:?}",get_exec_count());
    match cmd {
        LIBAFL_QEMU_COMMAND_SMM_REPORT_DUMMY_MEM => {
            unsafe {
                let dummy_virt_addr = arg1;
                DUMMY_MEMORY_VIRT_ADDR = dummy_virt_addr;
                let dummy_phy_addr = cpu.get_phys_addr_with_offset(dummy_virt_addr).unwrap();
                let dummy_host_addr = cpu.get_host_addr(dummy_phy_addr);
                DUMMY_MEMORY_HOST_PTR = dummy_host_addr as *mut u64;
                info!("dummy memory info {:#x} {:#x} {:?}",dummy_virt_addr,dummy_phy_addr,dummy_host_addr);
            }
        },
        LIBAFL_QEMU_COMMAND_SMM_REPORT_SMI_SELECT_INFO => {
            unsafe {
                SMI_SELECT_BUFFER_ADDR = arg1;
                SMI_SELECT_BUFFER_SIZE = arg2;
                let smi_select_buffer_phy_addr = cpu.get_phys_addr_with_offset(SMI_SELECT_BUFFER_ADDR).unwrap();
                let smi_select_buffer_host_addr = cpu.get_host_addr(smi_select_buffer_phy_addr);
                SMI_SELECT_BUFFER_HOST_PTR = smi_select_buffer_host_addr;
                info!("smi select buffer {:#x} {:#x} {:#x} {:?}",SMI_SELECT_BUFFER_ADDR, SMI_SELECT_BUFFER_SIZE, smi_select_buffer_phy_addr, SMI_SELECT_BUFFER_HOST_PTR);
            }
        },
        LIBAFL_QEMU_COMMAND_SMM_REPORT_COMMBUF_INFO => {
            unsafe {
                COMMBUF_ADDR = arg1;
                COMMBUF_SIZE = arg2;
                let commbuf_phy_addr = cpu.get_phys_addr_with_offset(COMMBUF_ADDR).unwrap();
                let commbuf_host_addr = cpu.get_host_addr(commbuf_phy_addr);
                COMMBUF_HOST_PTR = commbuf_host_addr;
                info!("comm buffer {:#x} {:#x} {:#x} {:?}",COMMBUF_ADDR, COMMBUF_SIZE, commbuf_phy_addr, COMMBUF_HOST_PTR);
            }
        },
        LIBAFL_QEMU_COMMAND_SMM_GET_SMI_SELECT_FUZZ_DATA => {
            if unsafe { IN_FUZZ } {
                match fuzz_input.get_smi_select_info_fuzz_data() {
                    Ok((fuzz_input_ptr, len)) => { 
                        unsafe { SMI_SELECT_BUFFER_HOST_PTR.copy_from(fuzz_input_ptr, len); }
                        ret = len as u64;
                    },
                    Err(io_err) => {    
                        match io_err {
                            StreamError::StreamNotFound(id) => {
                                fuzz_input.generate_init_stream(id);
                                match fuzz_input.get_smi_select_info_fuzz_data() {
                                    Ok((fuzz_input_ptr, len)) => { 
                                        unsafe { SMI_SELECT_BUFFER_HOST_PTR.copy_from(fuzz_input_ptr, len); }
                                        ret = len as u64;
                                    },
                                    _ => {    
                                        error!("smi select info generate error");
                                        exit_elegantly();
                                    },
                                }
                            },
                            _ => {
                                error!("smi select info get error");
                                exit_elegantly();
                            },
                        }
                    }
                }
            }
        },
        LIBAFL_QEMU_COMMAND_SMM_GET_COMMBUF_FUZZ_DATA => {
            let smi_index = arg1;
            let smi_invoke_times = arg2;
            if unsafe { IN_FUZZ } {
                match fuzz_input.get_commbuf_fuzz_data(smi_index, smi_invoke_times) {
                    Ok((fuzz_input_ptr,  claimed_len, actual_len)) => { 
                        let written_len = min(unsafe {COMMBUF_SIZE} as usize, actual_len);
                        unsafe { COMMBUF_HOST_PTR.copy_from(fuzz_input_ptr, written_len); }
                        ret = claimed_len as u64;
                    },
                    Err(io_err) => {    
                        match io_err {
                            StreamError::StreamNotFound(id) => {
                                fuzz_input.generate_init_stream(id);
                                match fuzz_input.get_commbuf_fuzz_data(smi_index, smi_invoke_times) {
                                    Ok((fuzz_input_ptr, claimed_len, actual_len)) => { 
                                        let written_len = min(unsafe {COMMBUF_SIZE} as usize, actual_len);
                                        unsafe { COMMBUF_HOST_PTR.copy_from(fuzz_input_ptr, written_len); }
                                        ret = claimed_len as u64;
                                    },
                                    _ => {    
                                        error!("comm buffer generate error");
                                        exit_elegantly();
                                    }
                                }
                            },
                            _ => {
                                ret = 0;
                            },
                        }
                    }
                }
            }
            
        },
        LIBAFL_QEMU_COMMAND_SMM_GET_PCD_FUZZ_DATA => {
            let len = arg1;
            if unsafe { IN_FUZZ } {
                match fuzz_input.get_pcd_fuzz_data(len) {
                    Ok((fuzz_input_ptr)) => { 
                        ret = match len {
                            1 => unsafe {*fuzz_input_ptr as u64},
                            _ => 0,
                        };
                    },
                    Err(io_err) => {    
                        match io_err {
                            StreamError::StreamNotFound(id) => {
                                fuzz_input.generate_init_stream(id);
                                match fuzz_input.get_pcd_fuzz_data(len) {
                                    Ok((fuzz_input_ptr)) => { 
                                        ret = match len {
                                            1 => unsafe { *fuzz_input_ptr as u64 },
                                            _ => 0,
                                        };
                                    },
                                    _ => {    
                                        error!("pcd data generate error");
                                        exit_elegantly();
                                    }
                                }
                            },
                            StreamError::StreamOutof(id, need_len) => {
                                let append_data = fuzz_input.append_temp_stream(id, need_len);
                                ret = match need_len {
                                    1 => append_data[0] as u64,
                                    _ => 0,
                                };
                                
                            },
                            _ => {
                                error!("pcd data get error");
                                exit_elegantly();
                            },
                        }
                    }
                }   
            }
        },
        LIBAFL_QEMU_COMMAND_SMM_REPORT_HOB_MEM => {
            unsafe {
                HOB_ADDR = arg1;
                HOB_SIZE = arg2;
            }
            info!("HOB addr {:#x} size {:#x}",arg1, arg2);
        },
        LIBAFL_QEMU_COMMAND_SMM_SMI_ENTER => {
            unsafe {
                IN_SMI = true;
            }
            enable_debug_trace();
        },
        LIBAFL_QEMU_COMMAND_SMM_SMI_EXIT => {
            unsafe {
                IN_SMI = false;
            }
            disable_debug_trace();
        },
        LIBAFL_QEMU_COMMAND_SMM_GET_VARIABLE_FUZZ_DATA => {
            let var_size = arg2;
            let variable_phy_addr = cpu.get_phys_addr_with_offset(arg1).unwrap();
            let variable_host_addr = cpu.get_host_addr(variable_phy_addr);
            
            if unsafe { IN_FUZZ } {
                match fuzz_input.get_variable_fuzz_data(var_size) {
                    Ok((fuzz_input_ptr)) => { 
                        unsafe {
                            variable_host_addr.copy_from(fuzz_input_ptr, var_size as usize);
                        }
                    },
                    Err(io_err) => {    
                        match io_err {
                            StreamError::StreamNotFound(id) => {
                                fuzz_input.generate_init_stream(id);
                                match fuzz_input.get_variable_fuzz_data(var_size) {
                                    Ok((fuzz_input_ptr)) => { 
                                        unsafe {
                                            variable_host_addr.copy_from(fuzz_input_ptr, var_size as usize);
                                        }
                                    },
                                    _ => {    
                                        error!("variable data generate error, request too much variable data {:}",var_size);
                                        exit_elegantly();
                                    }
                                }
                            },
                            StreamError::StreamOutof(id, need_len) => {
                                let append_data = fuzz_input.append_temp_stream(id, need_len);
                                unsafe {
                                    variable_host_addr.copy_from(append_data.as_ptr(), need_len);
                                }
                            },
                            _ => {
                                error!("variable data get error");
                                exit_elegantly();
                            },
                        }
                    }
                }   
            }
        },
        LIBAFL_QEMU_COMMAND_SMM_GET_SMI_GROUP_INDEX_FUZZ_DATA => {
            if unsafe { IN_FUZZ } {
                match fuzz_input.get_smi_group_index_fuzz_data() {
                    Ok((group_index)) => { 
                        ret = group_index as u64;
                    },
                    Err(io_err) => {    
                        match io_err {
                            StreamError::StreamNotFound(id) => {
                                fuzz_input.generate_init_stream(id);
                                match fuzz_input.get_smi_group_index_fuzz_data() {
                                    Ok((group_index)) => { 
                                        ret = group_index as u64;
                                    },
                                    _ => {    
                                        error!("smi group index data generate error");
                                        exit_elegantly();
                                    }
                                }
                            },
                            StreamError::StreamOutof(id, need_len) => {
                                let append_data = fuzz_input.append_temp_stream(id, need_len);
                                ret = append_data[0] as u64;
                            },
                            _ => {
                                error!("smi group index data get error");
                                exit_elegantly();
                            },
                        }
                    }
                }   
            }
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
        _ => { 
            error!("backdoor wrong cmd {:#x}",cmd); 
            exit_elegantly()
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

pub fn bbl_debug(cpu : CPU) {
    if unsafe {DEBUG_TRACE_ENABLE == true}
    {
        let pc : GuestReg = cpu.read_reg(Regs::Pc).unwrap();
        let rax : GuestReg = cpu.read_reg(Regs::Rax).unwrap();
        let rbx : GuestReg = cpu.read_reg(Regs::Rbx).unwrap();
        let rcx : GuestReg = cpu.read_reg(Regs::Rcx).unwrap();
        let rdx : GuestReg = cpu.read_reg(Regs::Rdx).unwrap();
        let rsi : GuestReg = cpu.read_reg(Regs::Rsi).unwrap();
        let rdi : GuestReg = cpu.read_reg(Regs::Rdi).unwrap();
        info!("bbl-> {} pc:{pc:#x} rax:{rax:#x} rbx:{rbx:#x} rcx:{rcx:#x} rdx:{rdx:#x} rsi:{rsi:#x} rdi:{rdi:#x}",get_exec_count());
    }
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