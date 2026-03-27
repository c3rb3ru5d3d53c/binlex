pub use crate::core::Architecture as ProcessorArchitecture;
pub use crate::core::OperatingSystem as ProcessorOs;
pub use crate::core::Transport as ProcessorTransport;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum ProcessorTarget {
    Instruction,
    Block,
    Function,
    Graph,
    Complete,
}
