pub mod vex;

use crate::processing::processor::ProcessorDispatch;

pub fn dispatch_by_name(name: &str) -> Option<Box<dyn ProcessorDispatch>> {
    match name {
        "vex" => Some(Box::new(vex::VexProcessor)),
        _ => None,
    }
}
