// MIT License
//
// Copyright (c) [2025] [c3rb3ru5d3d53c]
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MirTypeKind {
    Void,
    Integer,
    Float,
    Pointer,
    Memory,
    Custom,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MirType {
    Void,
    Integer(u16),
    Float(u16),
    Pointer { pointee: Box<MirType> },
    Memory,
    Custom { name: String },
}

impl MirType {
    pub fn kind(&self) -> MirTypeKind {
        match self {
            Self::Void => MirTypeKind::Void,
            Self::Integer(_) => MirTypeKind::Integer,
            Self::Float(_) => MirTypeKind::Float,
            Self::Pointer { .. } => MirTypeKind::Pointer,
            Self::Memory => MirTypeKind::Memory,
            Self::Custom { .. } => MirTypeKind::Custom,
        }
    }

    pub fn void() -> Self {
        Self::Void
    }

    pub fn integer(bits: u16) -> Self {
        Self::Integer(bits)
    }

    pub fn float(bits: u16) -> Self {
        Self::Float(bits)
    }

    pub fn pointer(pointee: MirType) -> Self {
        Self::Pointer {
            pointee: Box::new(pointee),
        }
    }

    pub fn memory() -> Self {
        Self::Memory
    }

    pub fn custom(name: String) -> Self {
        Self::Custom { name }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MirCompareOperation {
    Eq,
    Ne,
    Ult,
    Ule,
    Ugt,
    Uge,
    Slt,
    Sle,
    Sgt,
    Sge,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MirCastOperation {
    ZeroExtend,
    SignExtend,
    Truncate,
    Bitcast,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MirTerminatorKind {
    Jump,
    CondBr,
    Return,
    Trap,
    Unreachable,
}
