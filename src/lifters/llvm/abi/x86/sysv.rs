use crate::Architecture;

pub fn supports(architecture: Architecture) -> bool {
    architecture == Architecture::AMD64
}
