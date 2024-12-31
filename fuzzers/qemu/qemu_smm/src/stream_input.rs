use libafl::inputs::multi::MultipartInput;
use libafl::inputs::BytesInput;
use std::cmp::min;
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
const SMI_GROUP_INDEX_MASK : u128 =  0x70000000000000000000000000000000;
const FUZZ_MEM_ENABLE_MASK : u128 =  0x80000000000000000000000000000000;
const VARIABLE_STREAM_MASK :u128 =   0x90000000000000000000000000000000;
const STREAM_MASK : u128 =           0xf0000000000000000000000000000000;


#[derive(Debug)]
pub enum StreamInfo {
    IoStream(u128, usize, usize, u8),
    DramStream(u128, usize, usize, u8),
    CommBufStream(u128, usize, usize, u8),
    MsrStream(u128, usize, usize, u8),
    StreamSeqStream(u128, usize, usize, u8),
    PcdStream(u128, usize, usize, u8),
    SmiGroupIndexStream(u128, usize, usize, u8),
    FuzzMemSwitchStream(u128, usize, usize, u8),
    VariableStream(u128, usize, usize, u8),
}

impl StreamInfo {
    fn new_io_stream(pc : u64, addr : u64) -> Self {
        StreamInfo::IoStream(((pc as u128) << 64) | (addr as u128) | IO_STREAM_MASK, 32, 128, 1)
    }
    fn new_dram_stream() -> Self {
        StreamInfo::DramStream(DRAM_STREAM_MASK, 256, 1024, 3)
    }
    fn new_comm_buf_stream(index : u64, times : u64) -> Self {
        StreamInfo::CommBufStream(COMMBUF_STREAM_MASK | ((index as u128) << 32) | (times as u128), 128, 256, 1)
    }
    fn new_msr_stream() -> Self {
        StreamInfo::MsrStream(MSR_STREAM_MASK, 64, 256, 1)
    }
    fn new_stream_seq_stream() -> Self {
        StreamInfo::StreamSeqStream(STREAMSEQ_STREAM_MASK, 4, 8, 1)
    }
    fn new_pcd_stream() -> Self {
        StreamInfo::PcdStream(PCD_STREAM_MASK, 16, 32, 1)
    }
    fn new_smi_group_index_stream() -> Self {
        StreamInfo::SmiGroupIndexStream(SMI_GROUP_INDEX_MASK, 1, 1, 1)
    }
    fn new_fuzz_mem_switch_stream() -> Self {
        StreamInfo::FuzzMemSwitchStream(FUZZ_MEM_ENABLE_MASK, 1, 1, 1)
    }
    fn new_variable_stream() -> Self {
        StreamInfo::VariableStream(VARIABLE_STREAM_MASK, 8192, 16348, 1)
    }
    fn get_id(&self) -> u128 {
        match self {
            StreamInfo::IoStream(id, _, _, _) => id.clone(),
            StreamInfo::DramStream(id, _, _, _) => id.clone(),
            StreamInfo::CommBufStream(id, _, _, _) => id.clone(),
            StreamInfo::MsrStream(id, _, _, _) => id.clone(),
            StreamInfo::StreamSeqStream(id, _, _, _) => id.clone(),
            StreamInfo::PcdStream(id, _, _, _) => id.clone(),
            StreamInfo::SmiGroupIndexStream(id, _, _, _) => id.clone(),
            StreamInfo::FuzzMemSwitchStream(id, _, _, _) => id.clone(),
            StreamInfo::VariableStream(id, _, _, _) => id.clone(),
        }
    }
    fn get_init_len(&self) -> usize {
        match self {
            StreamInfo::IoStream(_, init_len, _, _) => init_len.clone(),
            StreamInfo::DramStream(_, init_len, _, _) => init_len.clone(),
            StreamInfo::CommBufStream(_, init_len, _, _) => init_len.clone(),
            StreamInfo::MsrStream(_, init_len, _, _) => init_len.clone(),
            StreamInfo::StreamSeqStream(_, init_len, _, _) => init_len.clone(),
            StreamInfo::PcdStream(_, init_len, _, _) => init_len.clone(),
            StreamInfo::SmiGroupIndexStream(_, init_len, _, _) => init_len.clone(),
            StreamInfo::FuzzMemSwitchStream(_, init_len, _, _) => init_len.clone(),
            StreamInfo::VariableStream(_, init_len, _, _) => init_len.clone(),
        }
    }
    fn get_max_len(&self) -> usize {
        match self {
            StreamInfo::IoStream(_, _, max_len, _) => max_len.clone(),
            StreamInfo::DramStream(_, _, max_len, _) => max_len.clone(),
            StreamInfo::CommBufStream(_, _, max_len, _) => max_len.clone(),
            StreamInfo::MsrStream(_, _, max_len, _) => max_len.clone(),
            StreamInfo::StreamSeqStream(_, _, max_len, _) => max_len.clone(),
            StreamInfo::PcdStream(_, _, max_len, _) => max_len.clone(),
            StreamInfo::SmiGroupIndexStream(_, _, max_len, _) => max_len.clone(),
            StreamInfo::FuzzMemSwitchStream(_, _, max_len, _) => max_len.clone(),
            StreamInfo::VariableStream(_, _, max_len, _) => max_len.clone(),
        }  
    }
    fn get_weight(&self) -> u8 {
        match self {
            StreamInfo::IoStream(_, _, _, weight) => weight.clone(),
            StreamInfo::DramStream(_, _, _, weight) => weight.clone(),
            StreamInfo::CommBufStream(_, _, _, weight) => weight.clone(),
            StreamInfo::MsrStream(_, _, _, weight) => weight.clone(),
            StreamInfo::StreamSeqStream(_, _, _, weight) => weight.clone(),
            StreamInfo::PcdStream(_, _, _, weight) => weight.clone(),
            StreamInfo::SmiGroupIndexStream(_, _, _, weight) => weight.clone(),
            StreamInfo::FuzzMemSwitchStream(_, _, _, weight) => weight.clone(),
            StreamInfo::VariableStream(_, _, _, weight) => weight.clone(),
        }  
    }
}

#[derive(Debug)]
pub enum StreamError {
    StreamNotFound(StreamInfo),
    StreamOutof(StreamInfo, usize),
    LargeDatasize(u64),
    Unknown,
}
impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            StreamError::StreamNotFound(info) => write!(f, "Stream with ID {:#x} not found", info.get_id()),
            StreamError::StreamOutof(info,_) => write!(f, "Stream with ID {:#x} ran out of data", info.get_id()),
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
            return None;
        }
        let ret = unsafe { self.input.add(self.cursor as usize) };
        self.cursor += len;
        Some(ret)
    }
    pub fn get_input_all_ptr(&mut self) -> (*const u8, usize) {
        let ret = unsafe {(self.input.add(self.cursor as usize), self.len - self.cursor)};
        self.cursor = self.len;
        ret
    }
    pub fn get_used(&self) -> usize {
        self.cursor
    }
    pub fn get_unused(&self) -> usize {
        self.len - self.cursor
    }
}

pub enum StreamInput {
    NewStream(StreamInfo, Vec<u8>, RawStreamInput, Vec<u8>),
    OldStream(RawStreamInput, Vec<u8>),
}




impl StreamInput{
    pub fn from_fuzz(input : *const u8, len : usize) -> Self {
        StreamInput::OldStream(
            RawStreamInput {
                cursor : 0,
                input,
                len,
            },
            Vec::new(),
        )
    }
    pub fn from_new(info : StreamInfo, data : Vec<u8>) -> Self {
        let raw_ptr = data.as_ptr();
        let len = data.len();
        StreamInput::NewStream(
            info, 
            data, 
            RawStreamInput {
                cursor : 0,
                input : raw_ptr,
                len : len,
            },
            Vec::new(),
        )
    }
    pub fn get_id(&self) -> Option<u128> {
        match self {
            StreamInput::NewStream(info, _, _,_) => Some(info.get_id()),
            StreamInput::OldStream(_,_) => None,
        }
    }
    pub fn is_new_stream(&self) -> bool {
        match self {
            StreamInput::NewStream(_, _, _,_) => true,
            StreamInput::OldStream(_,_) => false,
        }
    }
    pub fn get_limit(&self) -> Option<usize> {
        match self {
            StreamInput::NewStream(info, _, _,_) => Some(info.get_max_len()),
            StreamInput::OldStream(_,_) => None,
        }
    }

    pub fn get_input_len_ptr(&mut self, len : usize) -> Option<*const u8> {
        match self {
            StreamInput::NewStream(_, _, stream,_) => stream.get_input_len_ptr(len),
            StreamInput::OldStream(stream,_) => stream.get_input_len_ptr(len),
        }
    }
    pub fn get_input_all_ptr(&mut self) -> (*const u8, usize) {
        match self {
            StreamInput::NewStream(_, _, stream,_) => stream.get_input_all_ptr(),
            StreamInput::OldStream(stream,_) => stream.get_input_all_ptr(),
        }
    }
    pub fn get_unused(&self) -> usize {
        match self {
            StreamInput::NewStream(_, _, stream,_) => stream.get_unused(),
            StreamInput::OldStream(stream,_) => stream.get_unused(),
        }
    }
    pub fn get_used(&self) -> usize {
        match self {
            StreamInput::NewStream(_, _, stream,_) => stream.get_used(),
            StreamInput::OldStream(stream,_) => stream.get_used(),
        }
    }
    pub fn get_new_stream(&self) -> Option<Vec<u8>> {
        match self {
            StreamInput::NewStream(_, stream , _, _) => Some(stream.clone()),
            StreamInput::OldStream(_,_) => None,
        }
    }
    pub fn get_append_stream(&self) -> Vec<u8> {
        match self {
            StreamInput::NewStream(_, _ , _, append_stream) => append_stream.clone(),
            StreamInput::OldStream(_,append_stream) => append_stream.clone(),
        }
    }
    pub fn get_weight(&self) -> u8 {
        match self {
            StreamInput::NewStream(info, _, _,_) => info.get_weight(),
            StreamInput::OldStream(_,_) => 0,
        }
    }
    pub fn append_new_data(&mut self, new_data : &Vec<u8>) {
        match self {
            StreamInput::NewStream(_, _ , _,append_stream) => append_stream.extend(new_data),
            StreamInput::OldStream(_,append_stream) => append_stream.extend(new_data),
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
                    return Err(StreamError::StreamOutof(stream_info, len as usize));
                }
            },
            std::collections::btree_map::Entry::Vacant(entry) => { 
                return Err(StreamError::StreamNotFound(stream_info));
            },
        }
    }
    pub fn get_msr_fuzz_data(&mut self) -> Result<(*const u8), StreamError> {
        let stream_info = StreamInfo::new_msr_stream();
        match self.inputs.entry(stream_info.get_id()) {
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                if let Some(fuzz_input_ptr) = entry.get_mut().get_input_len_ptr(8) {
                    return Ok(fuzz_input_ptr);
                }
                else {
                    return Err(StreamError::StreamOutof(stream_info, 8));
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
                let (fuzz_input_ptr,len) = entry.get_mut().get_input_all_ptr();
                return Ok((fuzz_input_ptr,len));
            },
            std::collections::btree_map::Entry::Vacant(entry) => { 
                return Err(StreamError::StreamNotFound(stream_info));
            },
        }
    }
    pub fn get_commbuf_fuzz_data(&mut self, index : u64, times : u64) -> Result<(*const u8, usize, usize), StreamError> {
        let stream_info = StreamInfo::new_comm_buf_stream(index, times);
        match self.inputs.entry(stream_info.get_id()) {
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                if let Some((claimed_len_ptr)) = entry.get_mut().get_input_len_ptr(8) { 
                    let claimed_len = unsafe {*(claimed_len_ptr as *const u64)} as usize;
                    let unused_len = entry.get().get_unused();
                    let actual_len = min(claimed_len, unused_len);
                    if let Some((fuzz_input_ptr)) = entry.get_mut().get_input_len_ptr(actual_len) { 
                        return Ok((fuzz_input_ptr, claimed_len, actual_len));
                    } else {
                        return Err(StreamError::Unknown);
                    }
                } else {
                    return Err(StreamError::StreamOutof(stream_info, 8));
                }
            },
            std::collections::btree_map::Entry::Vacant(entry) => { 
                return Err(StreamError::StreamNotFound(stream_info));
            },
        }
    }
    pub fn get_pcd_fuzz_data(&mut self, len : u64) -> Result<(*const u8), StreamError> {
        if len > 8 {
            return Err(StreamError::LargeDatasize(len));
        }
        let stream_info = StreamInfo::new_pcd_stream();
        match self.inputs.entry(stream_info.get_id()) {
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                if let Some(fuzz_input_ptr) = entry.get_mut().get_input_len_ptr(len as usize) {
                    return Ok(fuzz_input_ptr);
                }
                else {
                    return Err(StreamError::StreamOutof(stream_info, len as usize));
                }
            },
            std::collections::btree_map::Entry::Vacant(entry) => { 
                return Err(StreamError::StreamNotFound(stream_info));
            },
        }
    }
    fn get_unconsistent_dram_fuzz_data(&mut self, addr : u64, len : u64) -> Result<u64, StreamError> {
        if len > 16 {
            return Err(StreamError::LargeDatasize(len));
        }
        let stream_info = StreamInfo::new_dram_stream();
        match self.inputs.entry(stream_info.get_id()) {
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                if let Some(fuzz_input_ptr) = entry.get_mut().get_input_len_ptr(len as usize) {
                    let mut data : u64 = 0;
                    for i in 0..(len as usize) {
                        data = (data << 8) | unsafe { (*fuzz_input_ptr.add(i)) as u64 };
                    }
                    return Ok(data);
                }
                else {
                    return Err(StreamError::StreamOutof(stream_info, len as usize));
                }
            },
            std::collections::btree_map::Entry::Vacant(entry) => { 
                return Err(StreamError::StreamNotFound(stream_info));
            },
        }
    }
    fn get_consistent_dram_fuzz_data(&mut self, addr : u64, len : u64) -> Result<u64, StreamError> {
        if len > 16 {
            return Err(StreamError::LargeDatasize(len));
        }
        let stream_info = StreamInfo::new_dram_stream();
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
                                return Err(StreamError::StreamOutof(stream_info, uninit_addrs.len()));
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
    pub fn get_dram_fuzz_data(&mut self, addr : u64, len : u64, consistent : bool) -> Result<u64, StreamError> {
        if consistent {
            self.get_consistent_dram_fuzz_data(addr, len)
        } else {
            self.get_unconsistent_dram_fuzz_data(addr, len)
        }
    }

    pub fn get_fuzz_mem_switch_fuzz_data(&mut self) -> Result<u8, StreamError> {
        let stream_info = StreamInfo::new_fuzz_mem_switch_stream();
        match self.inputs.entry(stream_info.get_id()) {
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                if let Some(fuzz_input_ptr) = entry.get_mut().get_input_len_ptr(1) {
                    return Ok(unsafe {*fuzz_input_ptr});
                }
                else {
                    return Err(StreamError::StreamOutof(stream_info, 1));
                }
            },
            std::collections::btree_map::Entry::Vacant(entry) => { 
                return Err(StreamError::StreamNotFound(stream_info));
            },
        }
    }
    pub fn get_variable_fuzz_data(&mut self, len : u64) -> Result<(*const u8), StreamError> {
        let stream_info = StreamInfo::new_variable_stream();
        match self.inputs.entry(stream_info.get_id()) {
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                if let Some(fuzz_input_ptr) = entry.get_mut().get_input_len_ptr(len as usize) {
                    return Ok(fuzz_input_ptr);
                }
                else {
                    return Err(StreamError::StreamOutof(stream_info, len as usize));
                }
            },
            std::collections::btree_map::Entry::Vacant(entry) => { 
                return Err(StreamError::StreamNotFound(stream_info));
            },
        }
    }
    pub fn get_smi_group_index_fuzz_data(&mut self) -> Result<u8, StreamError> {
        let stream_info = StreamInfo::new_smi_group_index_stream();
        match self.inputs.entry(stream_info.get_id()) {
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                if let Some(fuzz_input_ptr) = entry.get_mut().get_input_len_ptr(1) {
                    return Ok(unsafe { *fuzz_input_ptr });
                }
                else {
                    return Err(StreamError::StreamOutof(stream_info, 1));
                }
            },
            std::collections::btree_map::Entry::Vacant(entry) => { 
                return Err(StreamError::StreamNotFound(stream_info));
            },
        }
    }
    pub fn set_dram_value(&mut self, addr : u64, len : u64, data : &[u8]) {
        self.sparse_memory.write_bytes(addr, len, data);
    }
    pub fn init_dram_value(&mut self, addr : u64, value : &Vec<u8>) {
        self.sparse_memory.init_bytes(addr, value);
    }

    pub fn generate_init_stream(&mut self, stream_info : StreamInfo) {
        let mut rng = rand::thread_rng();
        let mut stream = vec![0u8; stream_info.get_init_len()]; 
        rng.fill(&mut stream[..]);

        let tmp = StreamInput::from_new(stream_info, stream);
        self.inputs.insert(tmp.get_id().unwrap(), tmp);
    }

    pub fn append_temp_stream(&mut self, stream_info : StreamInfo, len : usize) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut append_data = vec![0u8; len]; 
        rng.fill(&mut append_data[..]);

        let stream: &mut StreamInput = self.inputs.get_mut(&stream_info.get_id()).unwrap();
        stream.append_new_data(&append_data);
        append_data
    }
}
        