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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InstructionSemantics {
    pub version: u32,
    pub status: SemanticStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub temporaries: Vec<SemanticTemporary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub effects: Vec<SemanticEffect>,
    pub terminator: SemanticTerminator,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<SemanticDiagnostic>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InstructionSemanticsJson {
    pub version: u32,
    pub status: SemanticStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub temporaries: Vec<SemanticTemporary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub effects: Vec<SemanticEffect>,
    pub terminator: SemanticTerminator,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<SemanticDiagnostic>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SemanticStatus {
    Partial,
    Complete,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SemanticTemporary {
    pub id: u32,
    pub bits: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SemanticLocation {
    Register {
        name: String,
        bits: u16,
    },
    Flag {
        name: String,
        bits: u16,
    },
    Pc {
        bits: u16,
    },
    Temp {
        id: u32,
        bits: u16,
    },
    Memory {
        space: AddressSpace,
        addr: Box<SemanticExpr>,
        bits: u16,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AddressSpace {
    Default,
    Stack,
    Heap,
    Global,
    Io,
    Segment { name: String },
    ArchSpecific { name: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SemanticEffect {
    Set {
        dst: SemanticLocation,
        value: SemanticExpr,
    },
    Store {
        space: AddressSpace,
        addr: SemanticExpr,
        value: SemanticExpr,
        bits: u16,
    },
    Fence {
        kind: FenceKind,
    },
    Trap {
        kind: TrapKind,
    },
    Intrinsic {
        name: String,
        args: Vec<SemanticExpr>,
        outputs: Vec<SemanticLocation>,
    },
    Nop,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FenceKind {
    Acquire,
    Release,
    AcquireRelease,
    SequentiallyConsistent,
    ArchSpecific { name: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TrapKind {
    Breakpoint,
    DivideError,
    Overflow,
    InvalidOpcode,
    GeneralProtection,
    PageFault,
    AlignmentFault,
    Syscall,
    Interrupt,
    ArchSpecific { name: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SemanticTerminator {
    FallThrough,
    Jump {
        target: SemanticExpr,
    },
    Branch {
        condition: SemanticExpr,
        true_target: SemanticExpr,
        false_target: SemanticExpr,
    },
    Call {
        target: SemanticExpr,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        return_target: Option<SemanticExpr>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        does_return: Option<bool>,
    },
    Return {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        value: Option<SemanticExpr>,
    },
    Unreachable,
    Trap,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SemanticExpr {
    Const {
        value: u128,
        bits: u16,
    },
    Read(Box<SemanticLocation>),
    Load {
        space: AddressSpace,
        addr: Box<SemanticExpr>,
        bits: u16,
    },
    Unary {
        op: SemanticUnaryOp,
        arg: Box<SemanticExpr>,
        bits: u16,
    },
    Binary {
        op: SemanticBinaryOp,
        left: Box<SemanticExpr>,
        right: Box<SemanticExpr>,
        bits: u16,
    },
    Cast {
        op: SemanticCastOp,
        arg: Box<SemanticExpr>,
        bits: u16,
    },
    Compare {
        op: SemanticCompareOp,
        left: Box<SemanticExpr>,
        right: Box<SemanticExpr>,
        bits: u16,
    },
    Select {
        condition: Box<SemanticExpr>,
        when_true: Box<SemanticExpr>,
        when_false: Box<SemanticExpr>,
        bits: u16,
    },
    Extract {
        arg: Box<SemanticExpr>,
        lsb: u16,
        bits: u16,
    },
    Concat {
        parts: Vec<SemanticExpr>,
        bits: u16,
    },
    Undefined {
        bits: u16,
    },
    Poison {
        bits: u16,
    },
    Intrinsic {
        name: String,
        args: Vec<SemanticExpr>,
        bits: u16,
    },
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum SemanticUnaryOp {
    Not,
    Neg,
    BitReverse,
    ByteSwap,
    CountLeadingZeros,
    CountTrailingZeros,
    PopCount,
    Sqrt,
    Abs,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum SemanticBinaryOp {
    Add,
    AddWithCarry,
    Sub,
    SubWithBorrow,
    Mul,
    UMulHigh,
    SMulHigh,
    UDiv,
    SDiv,
    URem,
    SRem,
    And,
    Or,
    Xor,
    Shl,
    LShr,
    AShr,
    RotateLeft,
    RotateRight,
    MinUnsigned,
    MinSigned,
    MaxUnsigned,
    MaxSigned,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum SemanticCastOp {
    ZeroExtend,
    SignExtend,
    Truncate,
    Bitcast,
    IntToFloat,
    FloatToInt,
    FloatExtend,
    FloatTruncate,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum SemanticCompareOp {
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
    Ordered,
    Unordered,
    Oeq,
    One,
    Olt,
    Ole,
    Ogt,
    Oge,
    Ueq,
    Une,
    UltFp,
    UleFp,
    UgtFp,
    UgeFp,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SemanticDiagnostic {
    pub kind: SemanticDiagnosticKind,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SemanticDiagnosticKind {
    UnsupportedInstruction,
    UnsupportedOperandForm,
    UnsupportedRegisterClass,
    UnsupportedVectorForm,
    UnsupportedFloatingPointForm,
    UnsupportedAtomicForm,
    PartialFlags,
    PartialMemoryModel,
    PartialExceptionModel,
    ArchSpecific { name: String },
}

impl InstructionSemantics {
    pub fn process(&self) -> InstructionSemanticsJson {
        InstructionSemanticsJson {
            version: self.version,
            status: self.status,
            temporaries: self.temporaries.clone(),
            effects: self.effects.clone(),
            terminator: self.terminator.clone(),
            diagnostics: self.diagnostics.clone(),
        }
    }
}

impl InstructionSemanticsJson {
    pub fn into_semantics(self) -> InstructionSemantics {
        InstructionSemantics {
            version: self.version,
            status: self.status,
            temporaries: self.temporaries,
            effects: self.effects,
            terminator: self.terminator,
            diagnostics: self.diagnostics,
        }
    }
}
