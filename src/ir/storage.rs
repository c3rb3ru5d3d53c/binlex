use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IrStorage {
    Register {
        name: String,
        bits: u16,
    },
    Stack {
        base: String,
        offset: i64,
        bits: u16,
    },
    Memory {
        address: String,
        bits: u16,
    },
    Expression {
        text: String,
        bits: u16,
    },
    CallReturn {
        target: Option<String>,
        index: usize,
        bits: u16,
    },
}

impl IrStorage {
    pub fn register(name: impl Into<String>, bits: u16) -> Self {
        Self::Register {
            name: name.into(),
            bits,
        }
    }

    pub fn stack(base: impl Into<String>, offset: i64, bits: u16) -> Self {
        Self::Stack {
            base: base.into(),
            offset,
            bits,
        }
    }

    pub fn memory(address: impl Into<String>, bits: u16) -> Self {
        Self::Memory {
            address: address.into(),
            bits,
        }
    }

    pub fn expression(text: impl Into<String>, bits: u16) -> Self {
        Self::Expression {
            text: text.into(),
            bits,
        }
    }

    pub fn call_return(target: Option<String>, index: usize, bits: u16) -> Self {
        Self::CallReturn {
            target,
            index,
            bits,
        }
    }
}
