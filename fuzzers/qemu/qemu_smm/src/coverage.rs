use std::collections::HashSet;
use once_cell::sync::Lazy;

static mut BBL_COV: Lazy<HashSet<u64>> = Lazy::new(|| {
    HashSet::new()
});

pub fn bbl_exec_cov_record_common(pc : u64) {
    if pc < 0x7000000 && pc >= 0x8000000 {
        return;
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