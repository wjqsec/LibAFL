use std::{path::PathBuf, process};
#[derive(Clone)]
pub enum RunMode {
    RunCopus(PathBuf),
    RunTestcase(PathBuf),
}