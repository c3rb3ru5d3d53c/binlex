use crate::Architecture;

pub mod amd64 {
    use crate::Architecture;

    pub const RAX_SEMANTIC_NAME: &str = "rax";
    pub const RCX_SEMANTIC_NAME: &str = "rcx";
    pub const R10_SEMANTIC_NAME: &str = "r10";
    pub const RDX_SEMANTIC_NAME: &str = "rdx";
    pub const R8_SEMANTIC_NAME: &str = "r8";
    pub const R9_SEMANTIC_NAME: &str = "r9";

    pub fn supports(architecture: Architecture) -> bool {
        architecture == Architecture::AMD64
    }
}

pub mod i386 {
    use crate::Architecture;

    pub const EAX_SEMANTIC_NAME: &str = "eax";
    pub const EDX_SEMANTIC_NAME: &str = "edx";
    pub const ECX_SEMANTIC_NAME: &str = "ecx";

    pub fn supports(architecture: Architecture) -> bool {
        architecture == Architecture::I386
    }
}

pub fn supports(architecture: Architecture) -> bool {
    amd64::supports(architecture) || i386::supports(architecture)
}
