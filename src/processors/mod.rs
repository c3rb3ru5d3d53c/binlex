#[cfg(not(target_os = "windows"))]
pub mod vex;

use crate::processing::processor::ProcessorDispatch;
use clap::ValueEnum;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, ValueEnum)]
pub enum ProcessorSelection {
    Vex,
}

#[cfg(not(target_os = "windows"))]
pub fn dispatch_by_name(name: &str) -> Option<Box<dyn ProcessorDispatch>> {
    match name {
        "vex" => Some(Box::new(vex::VexProcessor)),
        _ => None,
    }
}

#[cfg(target_os = "windows")]
pub fn dispatch_by_name(_name: &str) -> Option<Box<dyn ProcessorDispatch>> {
    None
}
