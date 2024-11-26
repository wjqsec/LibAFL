use libafl_qemu::{GuestAddr, GuestReg, CPU,Regs,Qemu};

use log::*;

use crate::{exit_elegantly, stream_input::*,SmmQemuExit};
use std::cell::UnsafeCell;
use once_cell::sync::Lazy;
use std::sync::{Arc, Mutex};
use std::vec::*;
use std::slice;
use crate::config::*;
use crate::smm_fuzz_qemu_cmds::*;

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

static mut NUM_BBL_DEBUG_TRACE : u64 = 0;
pub fn start_debug_trace(num_bbl : u64) {
    unsafe {
        NUM_BBL_DEBUG_TRACE = num_bbl;
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
                        Err(io_err) => {    
                            match io_err {
                                StreamError::StreamOutof(id) => {
                                    unsafe {
                                        NEXT_EXIT = Some(SmmQemuExit::StreamOutof);
                                    }
                                }
                                _ => {
                                    error!("io stream error {:?}",io_err);
                                    exit_elegantly();
                                }
                                
                            }
                        }
                    }
                },
                StreamError::StreamOutof(id) => {
                    unsafe {
                        NEXT_EXIT = Some(SmmQemuExit::StreamOutof);
                    }
                },
                _ => {
                    error!("io stream error {:?}",io_err);
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
        if io_err == 0 && addr != 0xb2 && addr != 0xb3 {
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
            exit_elegantly();
            0
        },
    };
    let addr = base + offset;
    debug!("pre_io_write {pc:#x} {addr:#x} {size:#x} {value:#x}");
}

pub fn pre_io_write_init_fuzz_phase(base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : *mut bool, cpu : CPU)
{
    unsafe {
        if IN_FUZZ == false {
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
    }
    pre_io_write_common(base, offset, size, data, handled, cpu);
}

fn pre_memrw_common(pc : GuestReg, addr : GuestAddr, size : u64 , out_addr : *mut GuestAddr, rw : u32, val : u128, fuzz_input : &mut StreamInputs, cpu : CPU)
{
    match rw { // read
        0 => {
            match fuzz_input.get_dram_fuzz_data(addr, size) {
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
                            match fuzz_input.get_dram_fuzz_data(addr,size) {
                                Ok(data) => { 
                                    unsafe { 
                                        *DUMMY_MEMORY_HOST_PTR = data;
                                        *out_addr = DUMMY_MEMORY_VIRT_ADDR;
                                    }
                                },
                                Err(io_err) => {    
                                    error!("dram fuzz data generate error {:?}",io_err);
                                    exit_elegantly();
                                }
                            }
                        },
                        StreamError::StreamOutof(id) => {
                            unsafe {
                                NEXT_EXIT = Some(SmmQemuExit::StreamOutof);
                                *DUMMY_MEMORY_HOST_PTR = 0x12345678deadbeef;
                                *out_addr = DUMMY_MEMORY_VIRT_ADDR;
                            }
                        }
                        _ => {
                            error!("dram fuzz data generate error {:?}",io_err);
                            exit_elegantly();
                        }
                    }
                }
            }
        },
        1 => {
            unsafe {
                *out_addr = DUMMY_MEMORY_VIRT_ADDR;
                fuzz_input.set_dram_value(addr, size, &val.to_le_bytes());
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
pub fn pre_memrw_init_fuzz_phase(pc : GuestReg, addr : GuestAddr, size : u64 , out_addr : *mut GuestAddr, rw : u32, val : u128, fuzz_input : &mut StreamInputs, cpu : CPU)
{
    unsafe {
        if IN_FUZZ == false {
            return;
        }
        if pc < CURRENT_MODULE_ADDR || pc >= CURRENT_MODULE_END {
            return;
        }
        if  addr < HOB_ADDR  || addr >= (HOB_ADDR + HOB_SIZE) { // HOB accees, needs to fuzz
            return;
        }
        if addr >= HOB_ADDR + 2 && addr < HOB_ADDR + 8 { // HOB length not to mutate
            return;
        }
    }
    if size > 16 {
        error!("pre_memrw_common get size large than 16 it is {:?}", size);
        exit_elegantly();
    }
    pre_memrw_common(pc, addr, size, out_addr, rw, val, fuzz_input, cpu);
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
    if addr >= unsafe {COMMBUF_ADDR} &&  addr <= unsafe {COMMBUF_ADDR + COMMBUF_SIZE} {  //outside comm buffer
        return;
    }
    if size > 16 {
        error!("pre_memrw_common get size large than 16 it is {:?}", size);
        exit_elegantly();
    }
    pre_memrw_common(pc, addr, size, out_addr, rw, val, fuzz_input, cpu);
}


fn rdmsr_common(in_ecx: u32, out_eax: *mut u32, out_edx: *mut u32,fuzz_input : &mut StreamInputs)
{
    match fuzz_input.get_msr_fuzz_data(8) {
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
                    match fuzz_input.get_msr_fuzz_data(8) {
                        Ok((fuzz_input_ptr)) => { 
                            unsafe { 
                                out_eax.copy_from(fuzz_input_ptr as *const u32, 1); 
                                out_edx.copy_from((fuzz_input_ptr as *const u32).offset(1), 1);
                            }
                        },
                        Err(io_err) => {    
                            error!("msr fuzz data generate error {:?}", io_err);
                            exit_elegantly();
                        }
                    }
                },
                StreamError::StreamOutof(id) => {
                    unsafe {
                        NEXT_EXIT = Some(SmmQemuExit::StreamOutof);
                    }
                }
                _ => {
                    error!("msr fuzz data generate error {:?}", io_err);
                    exit_elegantly();
                }
            }
        }
    }

    unsafe {
        let eax_info = *out_eax;
        let edx_info = *out_edx;
        info!("rdmsr {in_ecx:#x} {eax_info:#x} {edx_info:#x}");
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
            match fuzz_input.get_smi_select_info_fuzz_data() {
                Ok((fuzz_input_ptr, mut len)) => { 
                    unsafe { SMI_SELECT_BUFFER_HOST_PTR.copy_from(fuzz_input_ptr, len); }
                    ret = len as u64;
                },
                Err(io_err) => {    
                    match io_err {
                        StreamError::StreamNotFound(id) => {
                            fuzz_input.generate_init_stream(id);
                            match fuzz_input.get_smi_select_info_fuzz_data() {
                                Ok((fuzz_input_ptr, mut len)) => { 
                                    unsafe { SMI_SELECT_BUFFER_HOST_PTR.copy_from(fuzz_input_ptr, len); }
                                    ret = len as u64;
                                },
                                Err(io_err) => {    
                                    error!("smi info generate error {:?}",io_err);
                                    exit_elegantly();
                                }
                            }
                        },
                        _ => {
                            error!("smi info generate error {:?}",io_err);
                            exit_elegantly();
                        },
                    }
                }
            }
        },
        LIBAFL_QEMU_COMMAND_SMM_GET_COMMBUF_FUZZ_DATA => {
            unsafe {
                match fuzz_input.get_commbuf_fuzz_data(arg1, arg2) {
                    Ok((fuzz_input_ptr, mut len)) => { 
                        unsafe { COMMBUF_HOST_PTR.copy_from(fuzz_input_ptr, len); }
                        ret = len as u64;
                    },
                    Err(io_err) => {    
                        match io_err {
                            StreamError::StreamNotFound(id) => {
                                fuzz_input.generate_init_stream(id);
                                match fuzz_input.get_commbuf_fuzz_data(arg1, arg2) {
                                    Ok((fuzz_input_ptr, mut len)) => { 
                                        unsafe { COMMBUF_HOST_PTR.copy_from(fuzz_input_ptr, len); }
                                        ret = len as u64;
                                    },
                                    Err(io_err) => {    
                                        error!("comm buffer generate error {:?}",io_err);
                                        exit_elegantly();
                                    }
                                }
                            },
                            _ => {
                                error!("comm buffer generate error {:?}",io_err);
                                exit_elegantly();
                            },
                        }
                    }
                }
            }
        },
        LIBAFL_QEMU_COMMAND_SMM_GET_PCD_FUZZ_DATA => {
            unsafe {
                match fuzz_input.get_pcd_fuzz_data(arg1) {
                    Ok((fuzz_input_ptr)) => { 
                        ret = match arg1 {
                            1 => *fuzz_input_ptr as u64,
                            _ => 0,
                        };
                    },
                    Err(io_err) => {    
                        match io_err {
                            StreamError::StreamNotFound(id) => {
                                fuzz_input.generate_init_stream(id);
                                match fuzz_input.get_pcd_fuzz_data(arg1) {
                                    Ok((fuzz_input_ptr)) => { 
                                        ret = match arg1 {
                                            1 => *fuzz_input_ptr as u64,
                                            _ => 0,
                                        };
                                    },
                                    Err(io_err) => {    
                                        match io_err {
                                            StreamError::StreamOutof(id) => {
                                                unsafe {
                                                    NEXT_EXIT = Some(SmmQemuExit::StreamOutof);
                                                }
                                            },
                                            _ => {
                                                error!("pcd data generate error {:?}",io_err);
                                                exit_elegantly();
                                            }
                                        }
                                    }
                                }
                            },
                            StreamError::StreamOutof(id) => {
                                unsafe {
                                    NEXT_EXIT = Some(SmmQemuExit::StreamOutof);
                                }
                            },
                            _ => {
                                error!("pcd data generate error {:?}",io_err);
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
        },
        LIBAFL_QEMU_COMMAND_SMM_SMI_EXIT => {
            unsafe {
                IN_SMI = false;
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
    #[cfg(feature = "debug_trace")]
    {
        let pc : GuestReg = cpu.read_reg(Regs::Pc).unwrap();
        let rax : GuestReg = cpu.read_reg(Regs::Rax).unwrap();
        let rbx : GuestReg = cpu.read_reg(Regs::Rbx).unwrap();
        let rcx : GuestReg = cpu.read_reg(Regs::Rcx).unwrap();
        let rdx : GuestReg = cpu.read_reg(Regs::Rdx).unwrap();
        let rsi : GuestReg = cpu.read_reg(Regs::Rsi).unwrap();
        let rdi : GuestReg = cpu.read_reg(Regs::Rdi).unwrap();
        unsafe {
            if NUM_BBL_DEBUG_TRACE > 0 {
                info!("bbl-> {} pc:{pc:#x} rax:{rax:#x} rbx:{rbx:#x} rcx:{rcx:#x} rdx:{rdx:#x} rsi:{rsi:#x} rdi:{rdi:#x}",get_exec_count());
                NUM_BBL_DEBUG_TRACE -= 1;
            }  
        }
        
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