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


pub static mut DUMMY_MEMORY_VIRT_ADDR : u64 = 0;
pub static mut DUMMY_MEMORY_HOST_PTR : *mut u64 = 0 as *mut u64;

pub static mut IN_SMM_INIT : bool = false;
pub static mut IN_SMI_HANDLE : bool = false;

static mut EXEC_COUNT : u64 = 0;

static mut NEXT_EXIT : Option<SmmQemuExit> = None;  // use this variblae to prevent memory leak

static mut NUM_TIMEOUT_BBL : u64 = 0xffffffffff;


pub static mut GLOB_INPUT : *mut StreamInputs = std::ptr::null_mut() as *mut StreamInputs;

static mut SMI_SELECT_BUFFER_ADDR : u64 = 0;
static mut SMI_SELECT_BUFFER_SIZE : u64 = 0;

static mut COMMBUF_ADDR : u64 = 0;
static mut COMMBUF_SIZE : u64 = 0;

static mut DEBUG_TRACE : bool = false;
pub fn start_debug() {
    unsafe {
        DEBUG_TRACE = true;
    }
}
pub fn stop_debug() {
    unsafe {
        DEBUG_TRACE = false;
    }
}
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

fn post_io_read_common(base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : u32, 
                       fuzz_input : &mut StreamInputs, cpu : CPU)
{   
    if handled != 1 {
        return;
    }
    
    let pc : GuestReg = cpu.read_reg(Regs::Pc).unwrap();
    let addr = base + offset;
    
    match fuzz_input.get_io_fuzz_data(pc, addr, size as u64) {
        Ok(fuzz_input_ptr) => { 
            unsafe {data.copy_from(fuzz_input_ptr, size as usize);}
        },
        Err(io_err) => {    
            match io_err {
                StreamError::StreamNotFound(id) => {
                    let tmp_stream = vec![0u8 ; 32];
                    fuzz_input.insert_new_stream(id, tmp_stream);
                    match fuzz_input.get_io_fuzz_data(pc, addr, size as u64) {
                        Ok(fuzz_input_ptr) => { 
                            unsafe {data.copy_from(fuzz_input_ptr, size as usize);}
                        },
                        Err(io_err) => {    
                            match io_err {
                                StreamError::StreamNotFound(id) => {
                                    error!("io {id:#x} stream not found after added");
                                    exit_elegantly();
                                }
                                StreamError::StreamOutof(id) => {
                                    debug!("io {id:#x} stream used up");
                                    unsafe {
                                        NEXT_EXIT = Some(SmmQemuExit::StreamOutof);
                                    }
                                }
                            }
                        }
                    }
                },
                StreamError::StreamOutof(id) => {
                    debug!("io {id:#x} stream used up");
                    unsafe {
                        NEXT_EXIT = Some(SmmQemuExit::StreamOutof);
                    }
                    // cpu.exit_stream_outof();
                },
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

    debug!("post_io_read {pc:#x} {addr:#x} {size:#x} {value:#x} {handled:#x}");

}

pub fn post_io_read_init_fuzz_phase(base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : u32, 
    fuzz_input : &mut StreamInputs, cpu : CPU)
{
    unsafe {
        if IN_SMM_INIT == false {
            return;
        }
    }
    post_io_read_common(base, offset, size, data, handled, fuzz_input, cpu);
}
pub fn post_io_read_smm_fuzz_phase(base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : u32, 
    fuzz_input : &mut StreamInputs, cpu : CPU)
{
    unsafe {
        if IN_SMI_HANDLE == false {
            return;
        }
    }
    post_io_read_common(base, offset, size, data, handled, fuzz_input, cpu);
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
        if IN_SMM_INIT == false {
            return;
        }
    }
    pre_io_write_common(base, offset, size, data, handled, cpu);
}
pub fn pre_io_write_smm_fuzz_phase(base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : *mut bool, cpu : CPU)
{
    unsafe {
        if IN_SMI_HANDLE == false {
            return;
        }
    }
    pre_io_write_common(base, offset, size, data, handled, cpu);
}

fn pre_memrw_common(pc : GuestReg, addr : GuestAddr, size : u64 , out_addr : *mut GuestAddr, rw : u32, val : u128, fuzz_input : &mut StreamInputs, cpu : CPU)
{
    return;
    if addr >= 0x7000000 && addr <= 0x8000000 {
        return;
    }
    if size > 16 {
        error!("pre_memrw_common get size large than 8 it is {:?}", size);
        exit_elegantly();
    }

    if rw == 0 { // read
    }
    else if rw == 1 {   // write
        // fuzz_input.set_dram_value(addr, size, val);
    }
    else if rw == 2 {    // exch

    }
    else if rw == 3 {    // vec ldr

    }
    else if rw == 4 {    // vec str

    }
    debug!("memread {:#x} {:#x} {:#x} {:#x}",pc,addr,size,rw);
}
pub fn pre_memrw_init_fuzz_phase(pc : GuestReg, addr : GuestAddr, size : u64 , out_addr : *mut GuestAddr, rw : u32, val : u128, fuzz_input : &mut StreamInputs, cpu : CPU)
{
    unsafe {
        if IN_SMM_INIT == false {
            return;
        }
    }
    pre_memrw_common(pc, addr, size, out_addr, rw, val, fuzz_input, cpu);
}
pub fn pre_memrw_smm_fuzz_phase(pc : GuestReg, addr : GuestAddr, size : u64 , out_addr : *mut GuestAddr, rw : u32, val : u128, fuzz_input : &mut StreamInputs, cpu : CPU)
{
    unsafe {
        if IN_SMI_HANDLE == false {
            return;
        }
    }
    pre_memrw_common(pc, addr, size, out_addr, rw, val, fuzz_input, cpu);
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
        LIBAFL_QEMU_COMMAND_SMM_INIT_ENTER => {
            unsafe {
                IN_SMM_INIT = true;
            }
        }
        LIBAFL_QEMU_COMMAND_SMM_INIT_EXIT => {
            unsafe {
                IN_SMM_INIT = false;
            }
        },
        LIBAFL_QEMU_COMMAND_SMM_SMI_ENTER => {
            unsafe {
                IN_SMI_HANDLE = true;
            }
        },
        LIBAFL_QEMU_COMMAND_SMM_SMI_EXIT => {
            unsafe {
                IN_SMI_HANDLE = false;
            }
        },
        LIBAFL_QEMU_COMMAND_SMM_REPORT_SMI_SELECT_INFO => {
            unsafe {
                SMI_SELECT_BUFFER_ADDR = arg1;
                SMI_SELECT_BUFFER_SIZE = arg2;
            }
        },
        LIBAFL_QEMU_COMMAND_SMM_REPORT_COMMBUF_INFO => {
            unsafe {
                COMMBUF_ADDR = arg1;
                COMMBUF_SIZE = arg2;
            }
        },
        LIBAFL_QEMU_COMMAND_SMM_GET_SMI_SELECT_FUZZ_DATA => {
            match fuzz_input.get_smi_select_info() {
                Ok((fuzz_input_ptr, mut len)) => { 
                    unsafe { cpu.write_mem(unsafe{SMI_SELECT_BUFFER_ADDR}, unsafe {slice::from_raw_parts(fuzz_input_ptr, len)}); }
                    ret = len as u64;
                },
                Err(io_err) => {    
                    match io_err {
                        StreamError::StreamNotFound(id) => {
                            let tmp_stream = vec![0xabu8 ; 30];
                            fuzz_input.insert_new_stream(id, tmp_stream);
                            match fuzz_input.get_smi_select_info() {
                                Ok((fuzz_input_ptr, mut len)) => { 
                                    unsafe { cpu.write_mem(unsafe{SMI_SELECT_BUFFER_ADDR}, unsafe {slice::from_raw_parts(fuzz_input_ptr, len)}); }
                                    ret = len as u64;
                                },
                                Err(io_err) => {    
                                    error!("smi info generate error");
                                    exit_elegantly();
                                }
                            }
                        },
                        _ => {
                            error!("unexpected smi get info");
                            exit_elegantly();
                        },
                    }
                }
            }
        },
        LIBAFL_QEMU_COMMAND_SMM_GET_COMMBUF_FUZZ_DATA => {
            unsafe {
                match fuzz_input.get_commbuf_data(arg1, arg2) {
                    Ok((fuzz_input_ptr, mut len)) => { 
                        unsafe { cpu.write_mem(unsafe{COMMBUF_ADDR}, unsafe {slice::from_raw_parts(fuzz_input_ptr, len)}); }
                        ret = len as u64;
                    },
                    Err(io_err) => {    
                        match io_err {
                            StreamError::StreamNotFound(id) => {
                                let tmp_stream = vec![0u8 ; 64];
                                fuzz_input.insert_new_stream(id, tmp_stream);
                                match fuzz_input.get_commbuf_data(arg1, arg2) {
                                    Ok((fuzz_input_ptr, mut len)) => { 
                                        unsafe { cpu.write_mem(unsafe{COMMBUF_ADDR}, unsafe {slice::from_raw_parts(fuzz_input_ptr, len)}); }
                                        ret = len as u64;
                                    },
                                    Err(io_err) => {    
                                        error!("comm buffer generate error");
                                        exit_elegantly();
                                    }
                                }
                            },
                            _ => {
                                error!("unexpected get comm buffer");
                                exit_elegantly();
                            },
                        }
                    }
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
        let mut data : [u8 ; 16] = [0; 16];
        unsafe {
            cpu.read_mem(rax + 8,&mut data);
            if DEBUG_TRACE {
                info!("bbl-> {} pc:{pc:#x} rax:{rax:#x} rbx:{rbx:#x} rcx:{rcx:#x} rdx:{rdx:#x} rsi:{rsi:#x} rdi:{rdi:#x} {:02x}",get_exec_count(),data);
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