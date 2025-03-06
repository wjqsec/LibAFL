use std::collections::{HashSet, HashMap};
use std::str::FromStr;
use once_cell::sync::Lazy;
use std::{path::PathBuf, process};
use log::*;
use std::io::{self, BufRead};
use std::fs;
use std::fs::File;
use uuid::*;

struct ModuleCoverage {
    enable_cov : bool,
    start_addr : u64,
    end_addr : u64,
    offset : HashSet<u64>,
}


static mut BBL_COV: Lazy<HashMap<Uuid, ModuleCoverage>> = Lazy::new(|| {
    HashMap::new()
});


pub fn parse_cov_module_file(filename : &PathBuf) {
    if let Ok(file) = File::open(filename) {
        for line in io::BufReader::new(file).lines() {
            if let Ok(guid_lien) = line {
                if let Ok(guid) = Uuid::from_str(guid_lien.trim()) {
                    unsafe  {
                        BBL_COV.insert(guid, ModuleCoverage {
                            enable_cov : true,
                            start_addr : 0,
                            end_addr : 0,
                            offset : HashSet::new(),
                        });
                    }
                } 
            }
        }
    }
}

pub fn module_range(guid : &Uuid, start_addr : u64, end_addr : u64) {
    unsafe {
        if let Some(cov) = BBL_COV.get_mut(guid) {
            cov.start_addr = start_addr;
            cov.end_addr = end_addr;
        } else {
            BBL_COV.insert(guid.clone(), ModuleCoverage {
                enable_cov : false,
                start_addr : start_addr,
                end_addr : end_addr,
                offset : HashSet::new(),
            });
        }
    }
}

pub fn bbl_exec_cov_record_common(pc : u64) {
    for (guid,cov_info) in  unsafe { BBL_COV.iter_mut() } {
        if pc >= cov_info.start_addr && pc < cov_info.end_addr && cov_info.enable_cov {
            cov_info.offset.insert(pc - cov_info.start_addr);
        }
    }
}

pub fn num_bbl_covered() -> usize {
    let mut ret = 0;
    for (guid,cov_info) in  unsafe { BBL_COV.iter() } {
        ret += cov_info.offset.len();
    }
    ret
}

pub fn find_module_by_addr(addr : u64) -> (Option<Uuid>, u64) {
    for (guid,cov_info) in  unsafe { BBL_COV.iter_mut() } {
        if addr >= cov_info.start_addr && addr < cov_info.end_addr {
            return (Some(guid.clone()), addr - cov_info.start_addr);
        }
    }
    return (None, addr);
}

pub fn get_readable_addr(addr : u64) -> String {
    let (module, offset) = find_module_by_addr(addr);
    if let Some(module) = module {
        format!("{}:{:#x}",module.to_string(), offset)
    } else {
        format!("{:#x}",addr)
    }
}