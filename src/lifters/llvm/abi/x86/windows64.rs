use crate::Architecture;

pub const RAX_RETURN_SEMANTIC_NAME: &str = "rax";
pub const EAX_RETURN_SEMANTIC_NAME: &str = "eax";

pub fn supports(architecture: Architecture) -> bool {
    architecture == Architecture::AMD64
}
