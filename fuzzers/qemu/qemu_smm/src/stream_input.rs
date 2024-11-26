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
use rand::Rng;
use libafl_qemu::Qemu;
use std::fmt;

const IO_STREAM_MASK : u128 =        0x10000000000000000000000000000000;
const DRAM_STREAM_MASK : u128 =      0x20000000000000000000000000000000;
const COMMBUF_STREAM_MASK : u128 =   0x30000000000000000000000000000000;
const MSR_STREAM_MASK : u128 =       0x40000000000000000000000000000000;
const STREAMSEQ_STREAM_MASK : u128 = 0x50000000000000000000000000000000;
const PCD_STREAM_MASK : u128 =       0x60000000000000000000000000000000;
const STREAM_MASK : u128 =           0xf0000000000000000000000000000000;

#[derive(Debug)]
pub enum StreamInfo {
    IoStream(u128, usize, usize),
    DramStream(u128, usize, usize),
    CommBufStream(u128, usize, usize),
    MsrStream(u128, usize, usize),
    StreamSeqStream(u128, usize, usize),
    PcdStream(u128, usize, usize),
}

impl StreamInfo {
    fn new_io_stream(pc : u64, addr : u64) -> Self {
        StreamInfo::IoStream(((pc as u128) << 64) | (addr as u128) | IO_STREAM_MASK, 16, 32)
    }
    fn new_dram_stream() -> Self {
        StreamInfo::DramStream(DRAM_STREAM_MASK, 128, 256)
    }
    fn new_comm_buf_stream(index : u64, times : u64) -> Self {
        StreamInfo::CommBufStream(COMMBUF_STREAM_MASK | ((index as u128) << 32) | (times as u128), 64, 128)
    }
    fn new_msr_stream() -> Self {
        StreamInfo::MsrStream(MSR_STREAM_MASK, 16, 32)
    }
    fn new_stream_seq_stream() -> Self {
        StreamInfo::StreamSeqStream(STREAMSEQ_STREAM_MASK, 4, 8)
    }
    fn new_pcd_stream() -> Self {
        StreamInfo::PcdStream(PCD_STREAM_MASK, 16, 32)
    }
    fn get_id(&self) -> u128 {
        match self {
            StreamInfo::IoStream(id, _, _) => id.clone(),
            StreamInfo::DramStream(id, _, _) => id.clone(),
            StreamInfo::CommBufStream(id, _, _) => id.clone(),
            StreamInfo::MsrStream(id, _, _) => id.clone(),
            StreamInfo::StreamSeqStream(id, _, _) => id.clone(),
            StreamInfo::PcdStream(id, _, _) => id.clone(),
        }
    }
    fn get_init_len(&self) -> usize {
        match self {
            StreamInfo::IoStream(_, init_len, _) => init_len.clone(),
            StreamInfo::DramStream(_, init_len, _) => init_len.clone(),
            StreamInfo::CommBufStream(_, init_len, _) => init_len.clone(),
            StreamInfo::MsrStream(_, init_len, _) => init_len.clone(),
            StreamInfo::StreamSeqStream(_, init_len, _) => init_len.clone(),
            StreamInfo::PcdStream(_, init_len, _) => init_len.clone(),
        }
    }
    fn get_max_len(&self) -> usize {
        match self {
            StreamInfo::IoStream(_, _, max_len) => max_len.clone(),
            StreamInfo::DramStream(_, _, max_len) => max_len.clone(),
            StreamInfo::CommBufStream(_, _, max_len) => max_len.clone(),
            StreamInfo::MsrStream(_, _, max_len) => max_len.clone(),
            StreamInfo::StreamSeqStream(_, _, max_len) => max_len.clone(),
            StreamInfo::PcdStream(_, _, max_len) => max_len.clone(),
        }  
    }
}

#[derive(Debug)]
pub enum StreamError {
    StreamNotFound(StreamInfo),
    StreamOutof(StreamInfo),
    Unknown,
    LargeDatasize(u64),
}
impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            StreamError::StreamNotFound(info) => write!(f, "Stream with ID {:#x} not found", info.get_id()),
            StreamError::StreamOutof(info) => write!(f, "Stream with ID {:#x} ran out of data", info.get_id()),
            StreamError::Unknown => write!(f, "Stream error Unknown"),
            StreamError::LargeDatasize(size) => write!(f, "Stream error LargeDatasize {}",size),
        }
    }
}
impl Error for StreamError {}

pub struct RawStreamInput {
    cursor : usize,
    input : *const u8,
    len : usize,
}
impl RawStreamInput {
    pub fn get_input_len_ptr(&mut self, len : usize) -> Option<*const u8> {
        if self.cursor + len > self.len {
            self.cursor += len;  // we used more fuzz data, tell the fuzzer
            return None;
        }
        let ret = unsafe { self.input.add(self.cursor as usize) };
        self.cursor += len;
        Some(ret)
    }
    pub fn get_input_all_ptr(&mut self) -> Option<(*const u8, usize)> {
        if self.cursor >= self.len {
            return None;
        }
        let ret = unsafe {(self.input.add(self.cursor as usize), self.len - self.cursor)};
        self.cursor = self.len;
        Some(ret)
    }
    pub fn get_used(&self) -> usize {
        self.cursor
    }
}

pub enum StreamInput {
    NewStream(StreamInfo, Vec<u8>, RawStreamInput),
    OldStream(RawStreamInput),
}




impl StreamInput{
    pub fn from_fuzz(input : *const u8, len : usize) -> Self {
        StreamInput::OldStream(RawStreamInput {
            cursor : 0,
            input,
            len,
        })
    }
    pub fn from_new(info : StreamInfo, data : Vec<u8>) -> Self {
        let raw_ptr = data.as_ptr();
        let len = data.len();
        StreamInput::NewStream(info, data, RawStreamInput {
            cursor : 0,
            input : raw_ptr,
            len : len,
        })
    }
    pub fn get_id(&self) -> Option<u128> {
        match self {
            StreamInput::NewStream(info, _, _) => Some(info.get_id()),
            StreamInput::OldStream(_) => None,
        }
    }
    pub fn is_new_stream(&self) -> bool {
        match self {
            StreamInput::NewStream(_, _, _) => true,
            StreamInput::OldStream(_) => false,
        }
    }
    pub fn get_limit(&self) -> Option<usize> {
        match self {
            StreamInput::NewStream(info, _, _) => Some(info.get_max_len()),
            StreamInput::OldStream(_) => None,
        }
    }

    pub fn get_input_len_ptr(&mut self, len : usize) -> Option<*const u8> {
        match self {
            StreamInput::NewStream(_, _, stream) => stream.get_input_len_ptr(len),
            StreamInput::OldStream(stream) => stream.get_input_len_ptr(len),
        }
    }
    pub fn get_input_all_ptr(&mut self) -> Option<(*const u8, usize)> {
        match self {
            StreamInput::NewStream(_, _, stream) => stream.get_input_all_ptr(),
            StreamInput::OldStream(stream) => stream.get_input_all_ptr(),
        }
    }
    pub fn get_used(&self) -> usize {
        match self {
            StreamInput::NewStream(_, _, stream) => stream.get_used(),
            StreamInput::OldStream(stream) => stream.get_used(),
        }
    }
    pub fn get_stream_data(&self) -> Vec<u8> {
        match self {
            StreamInput::NewStream(_, data , _) => data.clone(),
            StreamInput::OldStream(_) => Vec::new(),
        }
    }
}

pub struct StreamInputs {
    inputs : BTreeMap<u128,StreamInput>,
    sparse_memory : SparseMemory,
}
impl StreamInputs {
    pub fn get_streams(&self) -> &BTreeMap<u128,StreamInput> {
        &self.inputs
    }
    pub fn from_multiinput(input : & MultipartInput<BytesInput>) -> Self {
        let mut inputs = BTreeMap::new();
        for (id, part) in input.iter()  {
            let tmp = StreamInput::from_fuzz(part.bytes().as_ptr() as *const u8, part.len());
            inputs.insert(*id, tmp);
        }
        StreamInputs { 
            inputs,
            sparse_memory : SparseMemory::new(),
        }
    }
    pub fn get_io_fuzz_data(&mut self, pc : u64, addr : u64, len : u64) -> Result<(*const u8), StreamError> {
        if len > 4 {
            return Err(StreamError::LargeDatasize(len));
        }
        let stream_info = StreamInfo::new_io_stream(pc, addr);
        match self.inputs.entry(stream_info.get_id()) {
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                if let Some(fuzz_input_ptr) = entry.get_mut().get_input_len_ptr(len as usize) {
                    return Ok(fuzz_input_ptr);
                }
                else {
                    return Err(StreamError::StreamOutof(stream_info));
                }
            },
            std::collections::btree_map::Entry::Vacant(entry) => { 
                return Err(StreamError::StreamNotFound(stream_info));
            },
        }
    }
    pub fn get_msr_fuzz_data(&mut self, len : u64) -> Result<(*const u8), StreamError> {
        let stream_info = StreamInfo::new_msr_stream();
        match self.inputs.entry(stream_info.get_id()) {
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                if let Some(fuzz_input_ptr) = entry.get_mut().get_input_len_ptr(len as usize) {
                    return Ok(fuzz_input_ptr);
                }
                else {
                    return Err(StreamError::StreamOutof(stream_info));
                }
            },
            std::collections::btree_map::Entry::Vacant(entry) => { 
                return Err(StreamError::StreamNotFound(stream_info));
            },
        }
    }
    pub fn get_smi_select_info_fuzz_data(&mut self) -> Result<(*const u8, usize), StreamError> {
        let stream_info = StreamInfo::new_stream_seq_stream();
        match self.inputs.entry(stream_info.get_id()) {
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                if let Some((fuzz_input_ptr,len)) = entry.get_mut().get_input_all_ptr() {
                    return Ok((fuzz_input_ptr,len));
                }
                else {
                    return Err(StreamError::StreamOutof(stream_info));
                }
            },
            std::collections::btree_map::Entry::Vacant(entry) => { 
                return Err(StreamError::StreamNotFound(stream_info));
            },
        }
    }
    pub fn get_commbuf_fuzz_data(&mut self, index : u64, times : u64) -> Result<(*const u8, usize), StreamError> {
        let stream_info = StreamInfo::new_comm_buf_stream(index, times);
        match self.inputs.entry(stream_info.get_id()) {
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                if let Some((fuzz_input_ptr,len)) = entry.get_mut().get_input_all_ptr() {
                    return Ok((fuzz_input_ptr,len));
                }
                else {
                    return Err(StreamError::StreamOutof(stream_info));
                }
            },
            std::collections::btree_map::Entry::Vacant(entry) => { 
                return Err(StreamError::StreamNotFound(stream_info));
            },
        }
    }
    pub fn get_pcd_fuzz_data(&mut self, len : u64) -> Result<(*const u8), StreamError> {
        let stream_info = StreamInfo::new_pcd_stream();
        match self.inputs.entry(stream_info.get_id()) {
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                if let Some(fuzz_input_ptr) = entry.get_mut().get_input_len_ptr(len as usize) {
                    return Ok(fuzz_input_ptr);
                }
                else {
                    return Err(StreamError::StreamOutof(stream_info));
                }
            },
            std::collections::btree_map::Entry::Vacant(entry) => { 
                return Err(StreamError::StreamNotFound(stream_info));
            },
        }
    }
    pub fn get_dram_fuzz_data(&mut self, addr : u64, len : u64) -> Result<u64, StreamError> {
        if len > 8 {
            return Err(StreamError::LargeDatasize(len));
        }
        let stream_info = StreamInfo::new_dram_stream();
        let mut ret : u64 = 0;
        match self.sparse_memory.read_bytes(addr, len) {
            Ok(data) => {
                return Ok(data);
            },
            Err(err) => {
                if let DramError::Uninit(uninit_addrs) = err {
                    match self.inputs.entry(stream_info.get_id()) {
                        std::collections::btree_map::Entry::Occupied(mut entry) => {
                            if let Some(mut fuzz_input_ptr) = entry.get_mut().get_input_len_ptr(uninit_addrs.len()) {
                                for uninit_addr in uninit_addrs {
                                    self.sparse_memory.write_byte(uninit_addr, unsafe { fuzz_input_ptr.read() });
                                    fuzz_input_ptr = unsafe { fuzz_input_ptr.add(1) };
                                }
                                if let Ok(data) = self.sparse_memory.read_bytes(addr, len) {
                                    return Ok(data);
                                } else {
                                    return Err(StreamError::Unknown);
                                }
                            }
                            else {
                                return Err(StreamError::StreamOutof(stream_info));
                            }
                        },
                        std::collections::btree_map::Entry::Vacant(entry) => { 
                            return Err(StreamError::StreamNotFound(stream_info));
                        },
                    }
                }
                return Err(StreamError::Unknown);
            },
        }
    }

    pub fn set_dram_value(&mut self, addr : u64, len : u64, data : &[u8]) {
        self.sparse_memory.write_bytes(addr, len, data);
    }

    pub fn generate_init_stream(&mut self, stream_info : StreamInfo) {
        let mut rng = rand::thread_rng();
        let mut stream = vec![0u8; stream_info.get_init_len()]; 
        rng.fill(&mut stream[..]);

        let tmp = StreamInput::from_new(stream_info, stream);
        self.inputs.insert(tmp.get_id().unwrap(), tmp);
    }

}
        