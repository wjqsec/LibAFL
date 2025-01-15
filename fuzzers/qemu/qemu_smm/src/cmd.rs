use std::{path::PathBuf, process};
#[derive(Clone)]
pub enum RunMode {
    None,
    RunCopus(PathBuf),
    RunTestcase(PathBuf),
}