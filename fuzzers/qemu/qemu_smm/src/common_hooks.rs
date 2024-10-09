use libafl_qemu::{GuestAddr, GuestReg, CPU,Regs,Qemu};

use log::*;

use crate::{exit_elegantly, stream_input::*};
use std::cell::UnsafeCell;
use once_cell::sync::Lazy;
use std::sync::{Arc, Mutex};
use std::vec::*;
use crate::config::*;

pub static mut DUMMY_MEMORY_ADDR : UnsafeCell<u64> = UnsafeCell::new(0);

pub static mut IN_SMM_INIT : UnsafeCell<bool> = UnsafeCell::new(false);
pub static mut IN_SMI_HANDLE : UnsafeCell<bool> = UnsafeCell::new(false);

pub static mut NUM_STREAMS : UnsafeCell<u64> = UnsafeCell::new(0);


pub static NEW_STREAM : Lazy<Arc<Mutex<Vec<u128>>>> = Lazy::new( || Arc::new(Mutex::new(Vec::new())));
static mut EXEC_COUNT : UnsafeCell<u64> = UnsafeCell::new(0);

pub fn get_exec_count() -> u64 {
    let exec_count;
    unsafe { exec_count =  *EXEC_COUNT.get(); }
    exec_count
}
pub fn set_exec_count(val :u64) {
    unsafe { *EXEC_COUNT.get() =  val; }
}

fn post_io_read_common(base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : u32, 
                       fuzz_input : &mut StreamInputs, cpu : CPU)
{   
    if handled != 1 {
        return;
    }

    let pc : GuestReg = cpu.read_reg(Regs::Pc).unwrap();
    let addr = base + offset;
    
    // match fuzz_input.get_io_fuzz_value(pc, addr, size as u64, data) {
    //     Ok(_) => {},
    //     Err(io_err) => {
    //         match io_err {
    //             StreamError::StreamNotFound(id) => {
    //                 debug!("{id:#x} stream not found {handled}");
    //                 NEW_STREAM.lock().unwrap().push(id);
    //                 qemu.first_cpu().unwrap().exit_stream_notfound();
    //             },
    //             StreamError::StreamOutof(id) => {
    //                 debug!("{id:#x} stream used up");
    //                 qemu.first_cpu().unwrap().exit_stream_outof();
    //             },
    //         }
    //     }
    // }


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
        if *IN_SMM_INIT.get() == false {
            return;
        }
    }
    post_io_read_common(base, offset, size, data, handled, fuzz_input, cpu);
}
pub fn post_io_read_smm_fuzz_phase(base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : u32, 
    fuzz_input : &mut StreamInputs, cpu : CPU)
{
    unsafe {
        if *IN_SMI_HANDLE.get() == false {
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
    trace!("pre_io_write {pc:#x} {addr:#x} {size:#x} {value:#x}");
}

pub fn pre_io_write_init_fuzz_phase(base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : *mut bool, cpu : CPU)
{
    unsafe {
        if *IN_SMM_INIT.get() == false {
            return;
        }
    }
    pre_io_write_common(base, offset, size, data, handled, cpu);
}
pub fn pre_io_write_smm_fuzz_phase(base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : *mut bool, cpu : CPU)
{
    unsafe {
        if *IN_SMI_HANDLE.get() == false {
            return;
        }
    }
    pre_io_write_common(base, offset, size, data, handled, cpu);
}

fn pre_memrw_common(pc : GuestReg, addr : GuestAddr, size : u64 , out_addr : *mut GuestAddr)
{
    // debug!("memread {:#x} {:#x}",pc,addr);
}
pub fn pre_memrw_init_fuzz_phase(pc : GuestReg, addr : GuestAddr, size : u64 , out_addr : *mut GuestAddr)
{
    unsafe {
        if *IN_SMM_INIT.get() == false {
            return;
        }
    }
    pre_memrw_common(pc, addr, size, out_addr);
}
pub fn pre_memrw_smm_fuzz_phase(pc : GuestReg, addr : GuestAddr, size : u64 , out_addr : *mut GuestAddr)
{
    unsafe {
        if *IN_SMI_HANDLE.get() == false {
            return;
        }
    }
    pre_memrw_common(pc, addr, size, out_addr);
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
                *NUM_STREAMS.get() =  arg1; 
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
                *DUMMY_MEMORY_ADDR.get() = arg1;
            }
        },
        12 => {
            unsafe {
                *IN_SMM_INIT.get() = true;
            }
        }
        13 => {
            unsafe {
                *IN_SMM_INIT.get() = false;
            }
        },
        14 => {
            unsafe {
                *IN_SMI_HANDLE.get() = true;
            }
        },
        15 => {
            unsafe {
                *IN_SMI_HANDLE.get() = false;
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
    if get_exec_count() > INIT_PHASE_NUM_TIMEOUT_BBL {
        cpu.exit_timeout();
    }
    set_exec_count(get_exec_count() + 1);
}