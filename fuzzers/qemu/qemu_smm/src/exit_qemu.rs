use std::process::{Command, exit};
use log::*;

pub enum SmmQemuExit {
    Timeout,
    StreamNotFound,
    StreamOutof,
    Crash,  
}

pub fn exit_elegantly()
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

    exit(0);
}