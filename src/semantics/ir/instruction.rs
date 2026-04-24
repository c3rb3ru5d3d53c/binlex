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

mod semantic_const_value_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &u128, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u128, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            String(String),
            Unsigned(u64),
            Signed(i64),
        }

        match Repr::deserialize(deserializer)? {
            Repr::String(value) => value.parse::<u128>().map_err(serde::de::Error::custom),
            Repr::Unsigned(value) => Ok(value as u128),
            Repr::Signed(value) => u128::try_from(value).map_err(serde::de::Error::custom),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SemanticStatus {
    Partial,
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SemanticLocationKind {
    Register,
    Flag,
    ProgramCounter,
    Temporary,
    Memory,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SemanticTemporary {
    pub id: u32,
    pub bits: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SemanticLocation {
    Register {
        name: String,
        bits: u16,
    },
    Flag {
        name: String,
        bits: u16,
    },
    ProgramCounter {
        bits: u16,
    },
    Temporary {
        id: u32,
        bits: u16,
    },
    Memory {
        space: SemanticAddressSpace,
        addr: Box<SemanticExpression>,
        bits: u16,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SemanticAddressSpace {
    Default,
    State,
    Stack,
    Heap,
    Global,
    Io,
    Segment { name: String },
    ArchSpecific { name: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SemanticEffect {
    Set {
        dst: SemanticLocation,
        expression: SemanticExpression,
    },
    Store {
        space: SemanticAddressSpace,
        addr: SemanticExpression,
        expression: SemanticExpression,
        bits: u16,
    },
    MemorySet {
        space: SemanticAddressSpace,
        addr: SemanticExpression,
        value: SemanticExpression,
        count: SemanticExpression,
        element_bits: u16,
        decrement: SemanticExpression,
    },
    MemoryCopy {
        src_space: SemanticAddressSpace,
        src_addr: SemanticExpression,
        dst_space: SemanticAddressSpace,
        dst_addr: SemanticExpression,
        count: SemanticExpression,
        element_bits: u16,
        decrement: SemanticExpression,
    },
    AtomicCmpXchg {
        space: SemanticAddressSpace,
        addr: SemanticExpression,
        expected: SemanticExpression,
        desired: SemanticExpression,
        bits: u16,
        observed: SemanticLocation,
    },
    Fence {
        kind: SemanticFenceKind,
    },
    Trap {
        kind: SemanticTrapKind,
    },
    Architecture {
        name: String,
        args: Vec<SemanticExpression>,
        outputs: Vec<SemanticLocation>,
    },
    Intrinsic {
        name: String,
        args: Vec<SemanticExpression>,
        outputs: Vec<SemanticLocation>,
    },
    Nop,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SemanticEffectKind {
    Set,
    Store,
    MemorySet,
    MemoryCopy,
    AtomicCmpXchg,
    Fence,
    Trap,
    Architecture,
    Intrinsic,
    Nop,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SemanticFenceKind {
    Acquire,
    Release,
    AcquireRelease,
    SequentiallyConsistent,
    ArchSpecific { name: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SemanticTrapKind {
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

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SemanticTerminator {
    FallThrough,
    Jump {
        target: SemanticExpression,
    },
    Branch {
        condition: SemanticExpression,
        true_target: SemanticExpression,
        false_target: SemanticExpression,
    },
    Call {
        target: SemanticExpression,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        return_target: Option<SemanticExpression>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        does_return: Option<bool>,
    },
    Return {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expression: Option<SemanticExpression>,
    },
    Unreachable,
    Trap,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SemanticTerminatorKind {
    FallThrough,
    Jump,
    Branch,
    Call,
    Return,
    Unreachable,
    Trap,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SemanticExpression {
    Const {
        #[serde(with = "semantic_const_value_serde")]
        value: u128,
        bits: u16,
    },
    Read(Box<SemanticLocation>),
    Load {
        space: SemanticAddressSpace,
        addr: Box<SemanticExpression>,
        bits: u16,
    },
    Unary {
        op: SemanticOperationUnary,
        arg: Box<SemanticExpression>,
        bits: u16,
    },
    Binary {
        op: SemanticOperationBinary,
        left: Box<SemanticExpression>,
        right: Box<SemanticExpression>,
        bits: u16,
    },
    Cast {
        op: SemanticOperationCast,
        arg: Box<SemanticExpression>,
        bits: u16,
    },
    Compare {
        op: SemanticOperationCompare,
        left: Box<SemanticExpression>,
        right: Box<SemanticExpression>,
        bits: u16,
    },
    Select {
        condition: Box<SemanticExpression>,
        when_true: Box<SemanticExpression>,
        when_false: Box<SemanticExpression>,
        bits: u16,
    },
    Extract {
        arg: Box<SemanticExpression>,
        lsb: u16,
        bits: u16,
    },
    Concat {
        parts: Vec<SemanticExpression>,
        bits: u16,
    },
    Undefined {
        bits: u16,
    },
    Poison {
        bits: u16,
    },
    Architecture {
        name: String,
        args: Vec<SemanticExpression>,
        bits: u16,
    },
    Intrinsic {
        name: String,
        args: Vec<SemanticExpression>,
        bits: u16,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SemanticExpressionKind {
    Const,
    Read,
    Load,
    Unary,
    Binary,
    Cast,
    Compare,
    Select,
    Extract,
    Concat,
    Undefined,
    Poison,
    Architecture,
    Intrinsic,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SemanticOperationUnary {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SemanticOperationBinary {
    Add,
    AddWithCarry,
    Sub,
    SubWithBorrow,
    Mul,
    FAdd,
    FSub,
    FMul,
    FDiv,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SemanticOperationCast {
    ZeroExtend,
    SignExtend,
    Truncate,
    Bitcast,
    IntToFloat,
    FloatToInt,
    FloatExtend,
    FloatTruncate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SemanticOperationCompare {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SemanticOperation {
    Binary(SemanticOperationBinary),
    Unary(SemanticOperationUnary),
    Cast(SemanticOperationCast),
    Compare(SemanticOperationCompare),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SemanticDiagnostic {
    pub kind: SemanticDiagnosticKind,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

impl SemanticLocation {
    pub fn kind(&self) -> SemanticLocationKind {
        match self {
            Self::Register { .. } => SemanticLocationKind::Register,
            Self::Flag { .. } => SemanticLocationKind::Flag,
            Self::ProgramCounter { .. } => SemanticLocationKind::ProgramCounter,
            Self::Temporary { .. } => SemanticLocationKind::Temporary,
            Self::Memory { .. } => SemanticLocationKind::Memory,
        }
    }

    pub fn bits(&self) -> u16 {
        match self {
            Self::Register { bits, .. } => *bits,
            Self::Flag { bits, .. } => *bits,
            Self::ProgramCounter { bits } => *bits,
            Self::Temporary { bits, .. } => *bits,
            Self::Memory { bits, .. } => *bits,
        }
    }
}

impl SemanticEffect {
    pub fn kind(&self) -> SemanticEffectKind {
        match self {
            Self::Set { .. } => SemanticEffectKind::Set,
            Self::Store { .. } => SemanticEffectKind::Store,
            Self::MemorySet { .. } => SemanticEffectKind::MemorySet,
            Self::MemoryCopy { .. } => SemanticEffectKind::MemoryCopy,
            Self::AtomicCmpXchg { .. } => SemanticEffectKind::AtomicCmpXchg,
            Self::Fence { .. } => SemanticEffectKind::Fence,
            Self::Trap { .. } => SemanticEffectKind::Trap,
            Self::Architecture { .. } => SemanticEffectKind::Architecture,
            Self::Intrinsic { .. } => SemanticEffectKind::Intrinsic,
            Self::Nop => SemanticEffectKind::Nop,
        }
    }

    pub fn expression(&self) -> Option<&SemanticExpression> {
        match self {
            Self::Set { expression, .. } => Some(expression),
            Self::Store { expression, .. } => Some(expression),
            Self::MemorySet { value, .. } => Some(value),
            Self::AtomicCmpXchg { desired, .. } => Some(desired),
            _ => None,
        }
    }
}

impl SemanticTerminator {
    pub fn kind(&self) -> SemanticTerminatorKind {
        match self {
            Self::FallThrough => SemanticTerminatorKind::FallThrough,
            Self::Jump { .. } => SemanticTerminatorKind::Jump,
            Self::Branch { .. } => SemanticTerminatorKind::Branch,
            Self::Call { .. } => SemanticTerminatorKind::Call,
            Self::Return { .. } => SemanticTerminatorKind::Return,
            Self::Unreachable => SemanticTerminatorKind::Unreachable,
            Self::Trap => SemanticTerminatorKind::Trap,
        }
    }
}

impl SemanticExpression {
    pub fn kind(&self) -> SemanticExpressionKind {
        match self {
            Self::Const { .. } => SemanticExpressionKind::Const,
            Self::Read(_) => SemanticExpressionKind::Read,
            Self::Load { .. } => SemanticExpressionKind::Load,
            Self::Unary { .. } => SemanticExpressionKind::Unary,
            Self::Binary { .. } => SemanticExpressionKind::Binary,
            Self::Cast { .. } => SemanticExpressionKind::Cast,
            Self::Compare { .. } => SemanticExpressionKind::Compare,
            Self::Select { .. } => SemanticExpressionKind::Select,
            Self::Extract { .. } => SemanticExpressionKind::Extract,
            Self::Concat { .. } => SemanticExpressionKind::Concat,
            Self::Undefined { .. } => SemanticExpressionKind::Undefined,
            Self::Poison { .. } => SemanticExpressionKind::Poison,
            Self::Architecture { .. } => SemanticExpressionKind::Architecture,
            Self::Intrinsic { .. } => SemanticExpressionKind::Intrinsic,
        }
    }

    pub fn operation(&self) -> Option<SemanticOperation> {
        match self {
            Self::Binary { op, .. } => Some(SemanticOperation::Binary(*op)),
            Self::Unary { op, .. } => Some(SemanticOperation::Unary(*op)),
            Self::Cast { op, .. } => Some(SemanticOperation::Cast(*op)),
            Self::Compare { op, .. } => Some(SemanticOperation::Compare(*op)),
            _ => None,
        }
    }

    pub fn bits(&self) -> u16 {
        match self {
            Self::Const { bits, .. } => *bits,
            Self::Read(location) => location.bits(),
            Self::Load { bits, .. } => *bits,
            Self::Unary { bits, .. } => *bits,
            Self::Binary { bits, .. } => *bits,
            Self::Cast { bits, .. } => *bits,
            Self::Compare { bits, .. } => *bits,
            Self::Select { bits, .. } => *bits,
            Self::Extract { bits, .. } => *bits,
            Self::Concat { bits, .. } => *bits,
            Self::Undefined { bits } => *bits,
            Self::Poison { bits } => *bits,
            Self::Architecture { bits, .. } => *bits,
            Self::Intrinsic { bits, .. } => *bits,
        }
    }

    pub fn left(&self) -> Option<&SemanticExpression> {
        match self {
            Self::Binary { left, .. } | Self::Compare { left, .. } => Some(left),
            _ => None,
        }
    }

    pub fn right(&self) -> Option<&SemanticExpression> {
        match self {
            Self::Binary { right, .. } | Self::Compare { right, .. } => Some(right),
            _ => None,
        }
    }

    pub fn argument(&self) -> Option<&SemanticExpression> {
        match self {
            Self::Unary { arg, .. } | Self::Cast { arg, .. } | Self::Extract { arg, .. } => {
                Some(arg)
            }
            _ => None,
        }
    }

    pub fn condition(&self) -> Option<&SemanticExpression> {
        match self {
            Self::Select { condition, .. } => Some(condition),
            _ => None,
        }
    }

    pub fn when_true(&self) -> Option<&SemanticExpression> {
        match self {
            Self::Select { when_true, .. } => Some(when_true),
            _ => None,
        }
    }

    pub fn when_false(&self) -> Option<&SemanticExpression> {
        match self {
            Self::Select { when_false, .. } => Some(when_false),
            _ => None,
        }
    }

    pub fn address(&self) -> Option<&SemanticExpression> {
        match self {
            Self::Load { addr, .. } => Some(addr),
            _ => None,
        }
    }

    pub fn address_space(&self) -> Option<&SemanticAddressSpace> {
        match self {
            Self::Load { space, .. } => Some(space),
            _ => None,
        }
    }

    pub fn location(&self) -> Option<&SemanticLocation> {
        match self {
            Self::Read(location) => Some(location),
            _ => None,
        }
    }

    pub fn offset(&self) -> Option<u16> {
        match self {
            Self::Extract { lsb, .. } => Some(*lsb),
            _ => None,
        }
    }

    pub fn parts(&self) -> Option<&[SemanticExpression]> {
        match self {
            Self::Concat { parts, .. } => Some(parts),
            _ => None,
        }
    }

    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Architecture { name, .. } => Some(name.as_str()),
            Self::Intrinsic { name, .. } => Some(name.as_str()),
            _ => None,
        }
    }

    pub fn arguments(&self) -> Option<&[SemanticExpression]> {
        match self {
            Self::Architecture { args, .. } => Some(args),
            Self::Intrinsic { args, .. } => Some(args),
            _ => None,
        }
    }

    pub fn value(&self) -> Option<u128> {
        match self {
            Self::Const { value, .. } => Some(*value),
            _ => None,
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

#[cfg(test)]
mod tests {
    use super::{InstructionSemantics, SemanticExpression, SemanticStatus, SemanticTerminator};

    #[test]
    fn semantic_const_json_serializes_u128_as_string() {
        let semantics = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            temporaries: Vec::new(),
            effects: Vec::new(),
            terminator: SemanticTerminator::Return {
                expression: Some(SemanticExpression::Const {
                    value: u128::MAX,
                    bits: 128,
                }),
            },
            diagnostics: Vec::new(),
        };

        let json = serde_json::to_value(semantics.process()).expect("serialize semantics");
        let serialized = json
            .get("terminator")
            .and_then(|value| value.get("Return"))
            .and_then(|value| value.get("expression"))
            .and_then(|value| value.get("Const"))
            .and_then(|value| value.get("value"))
            .and_then(|value| value.as_str())
            .expect("const value should serialize as string");

        assert_eq!(serialized, u128::MAX.to_string());
    }

    #[test]
    fn semantic_const_json_deserializes_string_back_to_u128() {
        let value = u128::MAX.to_string();
        let payload = serde_json::json!({
            "version": 1,
            "status": "Complete",
            "terminator": {
                "Return": {
                    "expression": {
                        "Const": {
                            "value": value,
                            "bits": 128
                        }
                    }
                }
            },
            "temporaries": [],
            "effects": [],
            "diagnostics": []
        });

        let json: super::InstructionSemanticsJson =
            serde_json::from_value(payload).expect("deserialize semantics json");
        let semantics = json.into_semantics();

        match semantics.terminator {
            SemanticTerminator::Return {
                expression: Some(SemanticExpression::Const { value, bits }),
            } => {
                assert_eq!(value, u128::MAX);
                assert_eq!(bits, 128);
            }
            other => panic!("unexpected terminator: {:?}", other),
        }
    }
}
