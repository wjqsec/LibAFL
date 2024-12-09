use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

const NUM_PAGE_BYTES_SHIFT : usize = 8;
const NUM_PAGE_BYTES : usize = 1 << NUM_PAGE_BYTES_SHIFT;
const ADDR_MASK : u64 = 0xffffffffffffffff << NUM_PAGE_BYTES_SHIFT;
pub struct SparseMemory {
    memory : BTreeMap<u64,([u8;NUM_PAGE_BYTES], [bool;NUM_PAGE_BYTES])>,
}

#[derive(Debug)]
pub enum DramError {
    Uninit(Vec<u64>),
}
impl fmt::Display for DramError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DramError::Uninit(addrs) => write!(f, "DRAM {:?} is uninitialized",addrs),
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

    pub fn read_bytes(&mut self, addr : u64, len : u64) -> Result<u64,DramError> {
        let mut ret : u64 = 0;
        let mut uinit_addrs= Vec::new();

        let base_addr1  = addr &            ADDR_MASK;
        let base_addr2 = (addr + NUM_PAGE_BYTES as u64) & ADDR_MASK;

        let offset1 = (addr - base_addr1) as usize;
        let offset2 = 0 as usize;
        let (len1, len2) = if (len + addr) > base_addr2 {
            ((base_addr2 - addr) as usize, (len - (base_addr2 - addr)) as usize)
        } else {
            (len as usize, 0)
        };


        match self.memory.entry(base_addr1) {
            std::collections::btree_map::Entry::Occupied(entry) => {
                let (data, init) = entry.get();
                for i in 0..len1 {
                    if init[offset1 + i] == false {
                        uinit_addrs.push(addr + i as u64);
                    }
                    ret = (ret << 8) | data[offset1 + i] as u64;
                }
            },
            std::collections::btree_map::Entry::Vacant(entry) => {
                for i in 0..len1 {
                    uinit_addrs.push(addr + i as u64);
                }
                
            },  
        }
        if len2 == 0{
            if uinit_addrs.is_empty() {
                return Ok(ret);
            } else {
                return Err(DramError::Uninit(uinit_addrs));
            }
        }
        match self.memory.entry(base_addr2) {
            std::collections::btree_map::Entry::Occupied(entry) => {
                let (data, init) = entry.get();
                for i in 0..len2 {
                    if init[offset2 + i] == false {
                        uinit_addrs.push(base_addr2 + i as u64);
                    }
                    ret = (ret << 8) | data[offset2 + i] as u64;
                }
            },
            std::collections::btree_map::Entry::Vacant(entry) => {
                for i in 0..len2 {
                    uinit_addrs.push(base_addr2 + i as u64);
                }
            },  
        }
        
        if uinit_addrs.is_empty() {
            return Ok(ret);
        } else {
            return Err(DramError::Uninit(uinit_addrs));
        }
    }

    pub fn write_byte(&mut self, addr : u64, value : u8) {
        let mut base_addr  = addr & ADDR_MASK;
        let offset = (addr - base_addr) as usize;
        match self.memory.entry(base_addr) {
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                let (data, init) = entry.get_mut();
                data[offset] = value;
                init[offset] = true;
            },
            std::collections::btree_map::Entry::Vacant(entry) => {
                let mut data = [0;NUM_PAGE_BYTES];
                let mut init = [false;NUM_PAGE_BYTES];
                data[offset] = value;
                init[offset] = true;
                entry.insert((data,init));
            },
        }
    }

    pub fn write_bytes(&mut self, addr : u64, len : u64, data_input : &[u8]) {
        let base_addr1  = addr &            ADDR_MASK;
        let base_addr2 = (addr + NUM_PAGE_BYTES as u64) & ADDR_MASK;

        let offset1 = (addr - base_addr1) as usize;
        let offset2 = 0 as usize;
        let (len1, len2) = if (len + addr) > base_addr2 {
            ((base_addr2 - addr) as usize, (len - (base_addr2 - addr)) as usize)
        } else {
            (len as usize, 0)
        };
        match self.memory.entry(base_addr1) {
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                let (data, init) = entry.get_mut();
                data[offset1..(offset1+len1)].copy_from_slice(&data_input[0..len1]);
                init[offset1..(offset1+len1)].fill(true);
            },
            std::collections::btree_map::Entry::Vacant(entry) => {
                let mut data = [0;NUM_PAGE_BYTES];
                let mut init = [false;NUM_PAGE_BYTES];
                data[offset1..(offset1+len1)].copy_from_slice(&data_input[0..len1]);
                init[offset1..(offset1+len1)].fill(true);
                entry.insert((data,init));
            },  
        }
        if len2 == 0 {
            return;
        }
        match self.memory.entry(base_addr2) {
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                let (data, init) = entry.get_mut();
                data[offset2..(offset2+len2)].copy_from_slice(&data_input[len1..len as usize]);
                init[offset2..(offset2+len2)].fill(true);
            },
            std::collections::btree_map::Entry::Vacant(entry) => {
                let mut data = [0;NUM_PAGE_BYTES];
                let mut init = [false;NUM_PAGE_BYTES];
                data[offset2..(offset2+len2)].copy_from_slice(&data_input[len1..len as usize]);
                init[offset2..(offset2+len2)].fill(true);
                entry.insert((data,init));
            },  
        }
    }
    fn init_byte(&mut self, addr : u64, value : u8) {
        let mut base_addr  = addr & ADDR_MASK;
        let offset = (addr - base_addr) as usize;
        match self.memory.entry(base_addr) {
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                let (data, init) = entry.get_mut();
                if !init[offset] {
                    data[offset] = value;
                    init[offset] = true;
                }
            },
            std::collections::btree_map::Entry::Vacant(entry) => {
                let mut data = [0;NUM_PAGE_BYTES];
                let mut init = [false;NUM_PAGE_BYTES];
                data[offset] = value;
                init[offset] = true;
                entry.insert((data,init));
            },
        }
    }
    pub fn init_bytes(&mut self, addr : u64, value : &Vec<u8>) {
        for i in 0..value.len() {
            self.init_byte(addr + i as u64, value[i]);
        }
    }
}