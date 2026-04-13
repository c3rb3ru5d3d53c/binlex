use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Collection {
    #[serde(rename = "instructions")]
    Instruction,
    #[serde(rename = "blocks")]
    Block,
    #[serde(rename = "functions")]
    Function,
}

impl Collection {
    pub const fn all() -> &'static [Self] {
        &[Self::Instruction, Self::Block, Self::Function]
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Instruction => "instructions",
            Self::Block => "blocks",
            Self::Function => "functions",
        }
    }
}

impl fmt::Display for Collection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
