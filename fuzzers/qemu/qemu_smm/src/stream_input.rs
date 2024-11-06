use libafl::inputs::multi::MultipartInput;
use libafl::inputs::BytesInput;
use std::collections::BTreeMap;
use std::error;
use std::error::Error;
use libafl_qemu::QemuMemoryChunk;
use crate::exit_elegantly;
use crate::sparse_memory::*;
use crate::common_hooks::*;
use std::slice;
use libafl::inputs::HasMutatorBytes;
use libafl_bolts::HasLen;
use log::*;
use libafl_qemu::Qemu;
use std::fmt;
const IO_STREAM_MASK : u128 =        0x1000000000000000;
const DRAM_STREAM_MASK : u128 =      0x2000000000000000;
const COMMBUF_STREAM_MASK : u128 =   0x3000000000000000;
const MSR_STREAM_MASK : u128 =       0x4000000000000000;
const STREAMSEQ_STREAM_MASK : u128 = 0x5000000000000000;

const STREAM_MASK : u128 =           0xf000000000000000;
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
    tmp_generated : bool,
    limit : usize,
}

pub struct StreamInputs {
    inputs : BTreeMap<u128,StreamInput>,
    sparse_memory : SparseMemory,
    tmp_inputs : BTreeMap<u128,Vec<u8>>,
}

fn get_stream_limit(id : u128) -> usize {
    let mut limit = match (id & STREAM_MASK) {
        IO_STREAM_MASK => 64,
        DRAM_STREAM_MASK => 4096,
        COMMBUF_STREAM_MASK => 256,
        MSR_STREAM_MASK => 16,
        STREAMSEQ_STREAM_MASK => 32,
        _ => {
            error!("expected stream mask id {:#x}",id);
            exit_elegantly();
            0
        },
    };
    limit as usize
}

impl StreamInput{
    pub fn new (input : *const u8, len : usize, tmp_generated : bool, limit : usize) -> Self {
        StreamInput {
            cursor : 0,
            input,
            len,
            tmp_generated,
            limit,
        }
    }
    pub fn get_input_len_ptr(&mut self, len : usize) -> Result<*const u8, StreamError> {
        if self.cursor + len > self.len {
            return Err(StreamError::StreamOutof(0));
        }
        let ret = unsafe { self.input.add(self.cursor as usize) };
        self.cursor += len;
        Ok(ret)
    }
    pub fn get_input_all_ptr(&mut self) -> Result<(*const u8, usize), StreamError> {
        if self.cursor == self.len {
            return Err(StreamError::StreamOutof(0));
        }
        self.cursor = self.len;
        unsafe {Ok((self.input, self.len))}
    }
    pub fn is_tmp_generated(&self) -> bool {
        self.tmp_generated
    }
    pub fn get_used(&self) -> usize {
        self.cursor
    }
    pub fn get_limit(&self) -> usize {
        self.limit
    }
}


impl StreamInputs {
    pub fn get_streams(&self) -> &BTreeMap<u128,StreamInput> {
        &self.inputs
    }
    pub fn get_tmp_generated_stream(&self, id : &u128) -> Vec<u8> {
        self.tmp_inputs.get(id).unwrap().clone()
    }
    pub fn from_multiinput(input : & MultipartInput<BytesInput>) -> Self {
        let mut inputs = BTreeMap::new();
        for (id, part) in input.iter()  {
            let tmp = StreamInput::new(part.bytes().as_ptr() as *const u8, part.len(), false, 0);
            inputs.insert(*id, tmp);
        }
        StreamInputs { 
            inputs,
            sparse_memory : SparseMemory::new(),
            tmp_inputs : BTreeMap::new(),
        }
    }
    pub fn insert_new_stream(&mut self, id : u128, stream : Vec<u8>) {
        self.tmp_inputs.insert(id, stream);
        let tmp = StreamInput::new(self.tmp_inputs.get_mut(&id).unwrap().as_mut_ptr(), self.tmp_inputs.get(&id).unwrap().len(), true, get_stream_limit(id));
        self.inputs.insert(id, tmp);
    }
    pub fn get_io_fuzz_data(&mut self, pc : u64, addr : u64, len : u64) -> Result<(*const u8), StreamError> {
        let id = ((pc as u128) << 64) | (addr as u128) | IO_STREAM_MASK;
        // let id =(addr as u128) | IO_STREAM_MASK;
        match self.inputs.entry(id) {
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                if let Ok(fuzz_input_ptr) = entry.get_mut().get_input_len_ptr(len as usize) {
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
    pub fn get_smi_select_info(&mut self) -> Result<(*const u8, usize), StreamError> {
        let id = STREAMSEQ_STREAM_MASK;
        match self.inputs.entry(id) {
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                if let Ok((fuzz_input_ptr,len)) = entry.get_mut().get_input_all_ptr() {
                    return Ok((fuzz_input_ptr,len));
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
    pub fn get_commbuf_data(&mut self, index : u64, times : u64) -> Result<(*const u8, usize), StreamError> {
        let id = COMMBUF_STREAM_MASK | ((index as u128) << 32) | (times as u128);
        match self.inputs.entry(id) {
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                if let Ok((fuzz_input_ptr,len)) = entry.get_mut().get_input_all_ptr() {
                    return Ok((fuzz_input_ptr,len));
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
    pub fn get_dram_fuzz_data(&mut self, addr : u64, len : u64) -> Result<u64, StreamError> {
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
                            if let Ok(fuzz_input_ptr) = entry.get_mut().get_input_len_ptr(len as usize) {
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
}
        