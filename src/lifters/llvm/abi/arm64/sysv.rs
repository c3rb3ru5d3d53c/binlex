use crate::Architecture;

pub const X0_RETURN_SEMANTIC_NAME: &str = "reg_216";
pub const W0_RETURN_SEMANTIC_NAME: &str = "reg_185";

pub fn supports(architecture: Architecture) -> bool {
    architecture == Architecture::ARM64
}
