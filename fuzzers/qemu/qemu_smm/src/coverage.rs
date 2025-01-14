use std::collections::HashSet;
use once_cell::sync::Lazy;
use std::{path::PathBuf, process};
use log::*;
use std::io::{self, BufRead};
use std::fs;
use std::fs::File;

static mut BBL_COV: Lazy<HashSet<u64>> = Lazy::new(|| {
    HashSet::new()
});

static mut BBL_COV_FILTER: Lazy<Vec<(u64, u64)>> = Lazy::new(|| {
    Vec::new()
});

fn parse_hex_range(range: &str) -> Option<(u64, u64)> {
    let parts: Vec<&str> = range.split('-').collect();
    if parts.len() == 2 {
        let start = parts[0].trim().trim_start_matches("0x");
        let end = parts[1].trim().trim_start_matches("0x");
        if let (Ok(start_val), Ok(end_val)) = (u64::from_str_radix(start, 16), u64::from_str_radix(end, 16)) {
            return Some((start_val, end_val));
        }
    }
    None
}

fn add_cov_filter_range(start : u64, end : u64) {
    unsafe {
        BBL_COV_FILTER.push((start, end));
    }
}

pub fn parse_filter_file(filename : &PathBuf) {
    if let Ok(file) = File::open(filename) {
        for line in io::BufReader::new(file).lines() {
            if let Ok(range_str) = line {
                if let Some((start, end)) = parse_hex_range(&range_str) {
                    add_cov_filter_range(start, end);
                } else {
                    error!("filter range parse error");
                }
            }
        }
    }
}


pub fn bbl_exec_cov_record_common(pc : u64) {
    if pc < 0x7000000 && pc >= 0x8000000 {
        return;
    }
    for (start, end) in unsafe { BBL_COV_FILTER.iter() } {
        if pc >= *start && pc < *end {
            return;
        }
    }
    unsafe {
        BBL_COV.insert(pc);
    }
    
}

pub fn num_bbl_covered() -> usize {
    unsafe {
        BBL_COV.len()
    }

}