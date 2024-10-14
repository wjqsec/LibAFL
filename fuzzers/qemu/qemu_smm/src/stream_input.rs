use libafl::inputs::multi::MultipartInput;
use libafl::inputs::BytesInput;
use std::collections::BTreeMap;
use std::error::Error;
use libafl_qemu::QemuMemoryChunk;
use crate::sparse_memory::*;
use crate::common_hooks::*;
use std::slice;
use libafl::inputs::HasMutatorBytes;
use libafl_bolts::HasLen;
use libafl_qemu::Qemu;
use std::fmt;
const IO_STREAM_MASK : u128 = 0x0000000000000000;
const DRAM_STREAM_MASK : u128 = 0x1000000000000000;
const COMMBUF_STREAM_MASK : u128 = 0x2000000000000000;


#[derive(Debug)]
pub enum StreamError {
    StreamNotFound(u128),
    StreamOutof(u128),
}
impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            StreamError::StreamNotFound(id) => write!(f, "Stream with ID {} not found", id),
            StreamError::StreamOutof(id) => write!(f, "Stream with ID {} ran out of data", id),
        }
    }
}
impl Error for StreamError {}
pub struct StreamInput {
    cursor : usize,
    input : *const u8,
    len : usize,
}

pub struct StreamInputs {
    inputs : BTreeMap<u128,StreamInput>,
    sparse_memory : SparseMemory,
}

impl StreamInput{
    pub fn new (input : *const u8, len : usize) -> Self {
        StreamInput {
            cursor : 0,
            input,
            len,
        }
    }
    pub fn get_input_ptr(&mut self, len : usize) -> Result<*const u8, StreamError> {
        if self.cursor + len > self.len {
            return Err(StreamError::StreamOutof(0));
        }
        let ret = unsafe { self.input.add(self.cursor as usize) };
        self.cursor += len;
        Ok(ret)
    }
}


impl StreamInputs {
    pub fn from_multiinput(input : & MultipartInput<BytesInput>) -> Self {
        let mut inputs = BTreeMap::new();
        for (id, part) in input.iter()  {
            let tmp = StreamInput {
                cursor : 0,
                input: part.bytes().as_ptr() as *const u8,
                len : part.len(),
            };
            inputs.insert(*id, tmp);
        }
        StreamInputs { 
            inputs,
            sparse_memory : SparseMemory::new(),
        }
    }
    pub fn get_io_fuzz_value(&mut self, pc : u64, addr : u64, len : u64) -> Result<(*const u8), StreamError> {
        let id = ((pc as u128) << 64) | (addr as u128) | IO_STREAM_MASK;
        // let id =(addr as u128) | IO_STREAM_MASK;
        match self.inputs.entry(id) {
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                if let Ok(fuzz_input_ptr) = entry.get_mut().get_input_ptr(len as usize) {
                    return Ok(fuzz_input_ptr);
                }
                else {
                    return Err(StreamError::StreamOutof(id));
                }
            },
            std::collections::btree_map::Entry::Vacant(entry) => { 
                return Err(StreamError::StreamNotFound(id));
            },
        }
    }
    pub fn get_dram_fuzz_value(&mut self, addr : u64, len : u64) -> Result<u64, StreamError> {
        let id = DRAM_STREAM_MASK;
        let mut ret : u64 = 0;
        for i in 0..len {
            let read_addr = addr + i;
            match self.sparse_memory.read_byte(read_addr) {
                Ok(value) => {
                    ret = (ret << 8) | (value as u64)
                }
                Err(dram_error) => {
                    match self.inputs.entry(id) {
                        std::collections::btree_map::Entry::Occupied(mut entry) => {
                            if let Ok(fuzz_input_ptr) = entry.get_mut().get_input_ptr(len as usize) {
                                ret = (ret << 8) | (unsafe {*fuzz_input_ptr} as u64);
                            }
                            else {
                                return Err(StreamError::StreamOutof(id));
                            }
                        },
                        std::collections::btree_map::Entry::Vacant(entry) => { 
                            return Err(StreamError::StreamNotFound(id));
                        },
                    }
                }
            }
        }
        Ok(ret)
    }
    pub fn set_dram_value(&mut self, addr : u64, len : u64, value : u64) {
        self.sparse_memory.write(addr, len, &value.to_le_bytes());
    }

    pub fn set_dram_dummy_value(&mut self, value : u64) {
        self.sparse_memory.write_qemu_dummy(value);
    }


    

    pub fn write_comm_buf(&mut self, qemu : Qemu, comm_id : u64, addr : u64, max_size : u64)-> Result<usize, StreamError> {
        let id = (comm_id as u128) | COMMBUF_STREAM_MASK;
        match self.inputs.entry(id) {
            std::collections::btree_map::Entry::Occupied(entry) => {
                let mem_chunk = QemuMemoryChunk::virt(addr, max_size, qemu.first_cpu().unwrap());
                let written_len = mem_chunk.write(qemu, unsafe { slice::from_raw_parts(entry.get().input,entry.get().len) });
                return Ok(written_len as usize);
            },
            std::collections::btree_map::Entry::Vacant(entry) => { 
                return Err(StreamError::StreamNotFound(id));
            },
        }
    }
}
        