use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolType {
    Instruction,
    Block,
    Function,
}

impl SymbolType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Instruction => "instruction",
            Self::Block => "block",
            Self::Function => "function",
        }
    }
}

impl fmt::Display for SymbolType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
