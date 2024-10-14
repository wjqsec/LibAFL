use libafl_qemu::{GuestAddr, GuestReg, CPU,Regs,Qemu};

use log::*;

use crate::{exit_elegantly, stream_input::*,SmmQemuExit};
use std::cell::UnsafeCell;
use once_cell::sync::Lazy;
use std::sync::{Arc, Mutex};
use std::vec::*;
use crate::config::*;

pub static mut DUMMY_MEMORY_VIRT_ADDR : u64 = 0;
pub static mut DUMMY_MEMORY_HOST_PTR : *mut u64 = 0 as *mut u64;

pub static mut IN_SMM_INIT : bool = false;
pub static mut IN_SMI_HANDLE : bool = false;

pub static mut NUM_STREAMS : u64 = 0;
pub static NEW_STREAM : Lazy<Arc<Mutex<Vec<u128>>>> = Lazy::new( || Arc::new(Mutex::new(Vec::new())));

static mut EXEC_COUNT : u64 = 0;

static mut NEXT_EXIT : Option<SmmQemuExit> = None;  // use this variblae to prevent memory leak

pub static mut GLOB_INPUT : *mut StreamInputs = std::ptr::null_mut() as *mut StreamInputs;


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
    
    match fuzz_input.get_io_fuzz_value(pc, addr, size as u64) {
        Ok(fuzz_input_ptr) => { 
            unsafe {data.copy_from(fuzz_input_ptr, size as usize);}
        },
        Err(io_err) => {    
            match io_err {
                StreamError::StreamNotFound(id) => {
                    debug!("io {id:#x} stream not found");
                    NEW_STREAM.lock().unwrap().push(id);
                    unsafe {
                        NEXT_EXIT = Some(SmmQemuExit::StreamNotFound);
                    }
                    // cpu.exit_stream_notfound();
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
    if addr >= 0x7000000 && addr <= 0x8000000 {
        return;
    }
    if size > 16 {
        error!("pre_memrw_common get size large than 8 it is {:?}", size);
        exit_elegantly();
    }

    if rw == 0 { // read
        // match fuzz_input.get_dram_fuzz_value(addr, size) {
        //     Ok(value) => {
        //         fuzz_input.set_dram_dummy_value(value);
        //     }
        //     Err(stream_error) => {
        //         match stream_error {
        //             StreamError::StreamNotFound(id) => {
        //                 debug!("dram {id:#x} stream not found");
        //                 NEW_STREAM.lock().unwrap().push(id);
        //                 cpu.exit_stream_notfound();
        //             },
        //             StreamError::StreamOutof(id) => {
        //                 debug!("dram {id:#x} stream used up");
        //                 cpu.exit_stream_outof();
        //             },
        //         }
        //     }
        // }
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
pub fn backdoor_common(cpu : CPU)
{
    let pc : GuestReg = cpu.read_reg(Regs::Pc).unwrap();
    let cmd : GuestReg = cpu.read_reg(Regs::Rax).unwrap();
    let arg1 : GuestReg = cpu.read_reg(Regs::Rdi).unwrap();
    let arg2 : GuestReg = cpu.read_reg(Regs::Rsi).unwrap();
    let arg3 : GuestReg = cpu.read_reg(Regs::Rdx).unwrap();
    debug!("backdoor_common {cmd} {arg1:#x} {:?}",get_exec_count());
    match cmd {
        9 => {
            unsafe {
                NUM_STREAMS =  arg1; 
            }
        }
        10 => {
            // let mem_chunk = QemuMemoryChunk::virt(arg2, arg3, qemu.first_cpu().unwrap());
            // unsafe {
            //     let raw_input: *mut HashMap<u128,StreamInput> = *GLOB_INPUT.get();
            //     let id_entry = (*raw_input).get_mut(&(arg1 as u128));
            //     if let Some(entry) = id_entry {
            //         debug!("write stream {:#x} {:#x} {:#x}",arg1, arg2, arg3);
            //         let _ = mem_chunk.write(qemu, slice::from_raw_parts(entry.input,entry.len));
            //     }
            //     else {
            //         error!("cannot find stream {:#x}",arg1);
            //         exit_elegantly();
            //     }

            // }
            // debug!("backdoor write stream data {:#x}",arg1);
        },
        11 => {
            unsafe {
                let dummy_virt_addr = arg1;
                DUMMY_MEMORY_VIRT_ADDR = dummy_virt_addr;
                let dummy_phy_addr = cpu.get_phys_addr_with_offset(dummy_virt_addr).unwrap();
                let dummy_host_addr = cpu.get_host_addr(dummy_phy_addr);
                DUMMY_MEMORY_HOST_PTR = dummy_host_addr as *mut u64;
                info!("dummy memory info {:#x} {:#x} {:?}",dummy_virt_addr,dummy_phy_addr,dummy_host_addr);
            }
        },
        12 => {
            unsafe {
                IN_SMM_INIT = true;
            }
        }
        13 => {
            unsafe {
                IN_SMM_INIT = false;
            }
        },
        14 => {
            unsafe {
                IN_SMI_HANDLE = true;
            }
        },
        15 => {
            unsafe {
                IN_SMI_HANDLE = false;
            }
        },
        _ => { 
            error!("backdoor wrong cmd {:#x}",cmd); 
            exit_elegantly()
        },
    };
}

pub fn bbl_common(cpu : CPU) {
    let pc : GuestReg = cpu.read_reg(Regs::Pc).unwrap();
    let eax : GuestReg = cpu.read_reg(Regs::Rax).unwrap();
    let rdi : GuestReg = cpu.read_reg(Regs::Rdi).unwrap();
    
    trace!("bbl-> {} {pc:#x} {eax:#x} {rdi:#x}",get_exec_count());
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

    if get_exec_count() > INIT_PHASE_NUM_TIMEOUT_BBL {
        cpu.exit_timeout();
    }
    set_exec_count(get_exec_count() + 1);
}