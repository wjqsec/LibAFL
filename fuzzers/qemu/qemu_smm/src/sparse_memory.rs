use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use crate::DUMMY_MEMORY_HOST_PTR;
pub struct SparseMemory {
    memory : BTreeMap<u64,u8>,
}

#[derive(Debug)]
pub enum DramError {
    Uninit,
}
impl fmt::Display for DramError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DramError::Uninit => write!(f, "DRAM is uninitialized"),
        }
    }
}
impl Error for DramError {}

impl SparseMemory {
    pub fn new() -> Self  {
        SparseMemory {
            memory : BTreeMap::new(),
        }
    }

    pub fn read_byte(&mut self, addr : u64) -> Result<u8,DramError> {
        match self.memory.entry(addr) { 
            std::collections::btree_map::Entry::Occupied(entry) => {
                return Ok(entry.get().clone());
            },
            std::collections::btree_map::Entry::Vacant(entry) => {
                return Err(DramError::Uninit);
            },
        }
    }

    pub fn write_byte(&mut self, addr : u64, value : u8) {
        self.memory.entry(addr).and_modify(
            |value_ptr | *value_ptr = value
        ).or_insert(value);
    }

    pub fn write(&mut self, addr : u64, len : u64, data : &[u8]) {
        for i in 0..len {
            let access_addr = addr + i as u64;
            let insert_value = data[i as usize].try_into().unwrap();
            self.write_byte(access_addr, insert_value);
        }
    }
    pub fn write_qemu_dummy(&mut self, data : u64) {
        unsafe {
            *DUMMY_MEMORY_HOST_PTR = data;
        }
    }
    pub fn reset(&mut self) {
        self.memory.clear();
    }
}