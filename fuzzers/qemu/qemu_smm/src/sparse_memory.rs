use std::collections::BTreeMap;
use log::*;
use std::error::Error;
use std::fmt;
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

    pub fn write(&mut self, addr : u64, data : Vec<u8>) {
        for i in 0..data.len() {
            let access_addr = addr + i as u64;
            let insert_value = data[i];
            self.write_byte(access_addr, insert_value);
        }
    }
    pub fn reset(&mut self) {
        self.memory.clear();
    }
}