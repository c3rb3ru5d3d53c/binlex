use clap::ValueEnum;

pub use crate::core::Architecture as ProcessorArchitecture;
pub use crate::core::OperatingSystem as ProcessorOs;
pub use crate::core::Transport as ProcessorMode;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, ValueEnum)]
pub enum ProcessorSelection {
    Embeddings,
    Vex,
}

impl ProcessorSelection {
    pub fn to_vec() -> Vec<String> {
        vec![
            ProcessorSelection::Embeddings
                .to_possible_value()
                .unwrap()
                .get_name()
                .to_string(),
            ProcessorSelection::Vex
                .to_possible_value()
                .unwrap()
                .get_name()
                .to_string(),
        ]
    }

    pub fn to_list() -> String {
        ProcessorSelection::to_vec().join(", ")
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum ProcessorTarget {
    Instruction,
    Block,
    Function,
}
