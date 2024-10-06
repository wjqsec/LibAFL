use libafl_qemu::{GuestReg,GuestAddr};
use log::*;
use libafl_qemu::Qemu;
use crate::stream_input::*;
use std::cell::UnsafeCell;

static mut DUMMY_MEMORY_ADDR : UnsafeCell<u64> = UnsafeCell::new(0);
static mut IN_SMM_INIT : UnsafeCell<bool> = UnsafeCell::new(false);
static mut IN_SMI_HANDLE : UnsafeCell<bool> = UnsafeCell::new(false);
static mut NUM_STREAMS : UnsafeCell<u64> = UnsafeCell::new(0);

pub fn post_io_read_common(pc : GuestReg, base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : u32, 
                       fuzz_input : &mut StreamInputs, qemu : Qemu)
{
    unsafe {
        if *IN_SMM_INIT.get() == false && *IN_SMI_HANDLE.get() == false {
            return;
        }
    }
    let mut ret = false;
    let addr = base + offset;
    
    // match fuzz_input.get_io_fuzz_value(pc, addr, size as u64, data) {
    //     Ok(_) => {},
    //     Err(io_err) => {
    //         match io_err {
    //             StreamError::StreamNotFound(id) => {
    //                 // NEW_STREAM.lock().unwrap().push(id);
    //                 qemu.first_cpu().unwrap().exit_stream_notfound();
    //             },
    //             StreamError::StreamOutof(id) => {
    //                 qemu.first_cpu().unwrap().exit_stream_outof();
    //             },
    //         }
    //     }
    // }

    ret = true;
    let value = match size {
        1 => unsafe { *( data as *mut u8) as u64},
        2 => unsafe { *( data as *mut u16) as u64},
        4 => unsafe { *( data as *mut u32) as u64},
        8 => unsafe { *( data as *mut u64) as u64},
        _ => panic! ("post_io_read size error {:#x}!",size),
    };
    
    debug!("post_io_read {pc:#x} {addr:#x} {size:#x} {value:#x} {handled:#x}");

}



pub fn pre_io_write_common(pc : GuestReg, base : GuestAddr, offset : GuestAddr,size : usize, data : *mut u8, handled : *mut bool)
{
    unsafe {
        if *IN_SMM_INIT.get() == false && *IN_SMI_HANDLE.get() == false {
            return;
        }
    }
    let value = match size {
        1 => unsafe { *( data as *mut u8) as u64},
        2 => unsafe { *( data as *mut u16) as u64},
        4 => unsafe { *( data as *mut u32) as u64},
        8 => unsafe { *( data as *mut u64) as u64},
        _ => panic! ("pre_io_write size error {:#x}!",size),
    };
    let addr = base + offset;
    debug!("pre_io_write {pc:#x} {addr:#x} {size:#x} {value:#x}");
}

pub fn pre_memrw_common(pc : GuestReg, addr : GuestAddr, size : u64 , out_addr : *mut GuestAddr)
{
    unsafe {
        if *IN_SMM_INIT.get() == false && *IN_SMI_HANDLE.get() == false {
            return;
        }
    }
    // debug!("memread {:#x} {:#x}",pc,addr);
}

pub fn backdoor_common(qemu : Qemu,cmd : u64 , arg1 : u64, arg2 : u64, arg3 : u64)
{
    info!("backdoor_common {cmd} {arg1:#x}");
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
            //         panic!("cannot find stream {:#x}",arg1);
            //     }

            // }
            // debug!("backdoor write stream data {:#x}",arg1);
        },
        11 => {
            unsafe {
                *DUMMY_MEMORY_ADDR.get() = arg1;
            }
        }
        12 => {
            unsafe {
                *IN_SMM_INIT.get() = true;
            }
        }
        13 => {
            unsafe {
                *IN_SMM_INIT.get() = false;
            }
        }
        14 => {
            unsafe {
                *IN_SMI_HANDLE.get() = true;
            }
        }
        15 => {
            unsafe {
                *IN_SMI_HANDLE.get() = false;
            }
        }
        _ => { 
            panic!("backdoor wrong cmd {:#x}",cmd); 
        },
    };
}