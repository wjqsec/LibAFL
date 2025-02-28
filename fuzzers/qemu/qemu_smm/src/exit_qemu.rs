use std::process::{Command, exit};
use log::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
pub enum SmmQemuExit {
    Timeout,
    StreamNotFound,
    StreamOutof,
    Crash,  
}

pub enum ExitProcessType {
    Ok = 0,
    Error = 1,
}

static mut CTRLC_PRESSED : bool = false;

pub fn ctrlc_pressed() -> bool {
    unsafe {CTRLC_PRESSED}
}

pub fn exit_elegantly(code : ExitProcessType)
{
    let status = Command::new("stty")
    .arg("sane")
    .status()
    .expect("Failed to execute stty sane");

    if status.success() {
        info!("Terminal reset to sane mode.");
    } else {
        error!("Failed to reset terminal.");
    }

    exit(code as i32);
}

pub fn setup_ctrlc_handler() {
    ctrlc::set_handler(move || {
        unsafe {
            info!("Ctrl C");
            CTRLC_PRESSED = true;
        }
    }).expect("setup_ctrlc_handler error");
}