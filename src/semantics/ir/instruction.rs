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
    UIntToFloat,
    FloatToInt,
    FloatToUInt,
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

    pub fn set_version(&mut self, version: u32) {
        self.version = version;
    }

    pub fn set_status(&mut self, status: SemanticStatus) {
        self.status = status;
    }

    pub fn set_temporaries(&mut self, temporaries: Vec<SemanticTemporary>) {
        self.temporaries = temporaries;
    }

    pub fn set_effects(&mut self, effects: Vec<SemanticEffect>) {
        self.effects = effects;
    }

    pub fn set_terminator(&mut self, terminator: SemanticTerminator) {
        self.terminator = terminator;
    }

    pub fn set_diagnostics(&mut self, diagnostics: Vec<SemanticDiagnostic>) {
        self.diagnostics = diagnostics;
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

    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Register { name, .. } | Self::Flag { name, .. } => Some(name.as_str()),
            _ => None,
        }
    }

    pub fn set_kind(&mut self, kind: SemanticLocationKind) {
        let bits = self.bits();
        *self = default_location_for_kind(kind, bits);
    }

    pub fn set_bits(&mut self, bits: u16) {
        match self {
            Self::Register { bits: current, .. }
            | Self::Flag { bits: current, .. }
            | Self::ProgramCounter { bits: current }
            | Self::Temporary { bits: current, .. }
            | Self::Memory { bits: current, .. } => *current = bits,
        }
    }

    pub fn set_name(&mut self, name: impl Into<String>) -> Result<(), &'static str> {
        match self {
            Self::Register { name: current, .. } | Self::Flag { name: current, .. } => {
                *current = name.into();
                Ok(())
            }
            _ => Err("location name is only valid for register and flag locations"),
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

    pub fn location(&self) -> Option<&SemanticLocation> {
        match self {
            Self::Set { dst, .. } => Some(dst),
            Self::AtomicCmpXchg { observed, .. } => Some(observed),
            _ => None,
        }
    }

    pub fn set_kind(&mut self, kind: SemanticEffectKind) {
        *self = default_effect_for_kind(kind);
    }

    pub fn set_expression(&mut self, expression: SemanticExpression) -> Result<(), &'static str> {
        match self {
            Self::Set {
                expression: current, ..
            }
            | Self::Store {
                expression: current, ..
            }
            | Self::MemorySet { value: current, .. }
            | Self::AtomicCmpXchg {
                desired: current, ..
            } => {
                *current = expression;
                Ok(())
            }
            _ => Err("effect expression is not valid for this effect kind"),
        }
    }

    pub fn set_location(&mut self, location: SemanticLocation) -> Result<(), &'static str> {
        match self {
            Self::Set { dst, .. } => {
                *dst = location;
                Ok(())
            }
            Self::AtomicCmpXchg { observed, .. } => {
                *observed = location;
                Ok(())
            }
            _ => Err("effect location is not valid for this effect kind"),
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

    pub fn condition(&self) -> Option<&SemanticExpression> {
        match self {
            Self::Branch { condition, .. } => Some(condition),
            _ => None,
        }
    }

    pub fn true_target(&self) -> Option<&SemanticExpression> {
        match self {
            Self::Branch { true_target, .. } => Some(true_target),
            _ => None,
        }
    }

    pub fn false_target(&self) -> Option<&SemanticExpression> {
        match self {
            Self::Branch { false_target, .. } => Some(false_target),
            _ => None,
        }
    }

    pub fn target(&self) -> Option<&SemanticExpression> {
        match self {
            Self::Jump { target } | Self::Call { target, .. } => Some(target),
            _ => None,
        }
    }

    pub fn return_target(&self) -> Option<&SemanticExpression> {
        match self {
            Self::Call { return_target, .. } => return_target.as_ref(),
            _ => None,
        }
    }

    pub fn does_return(&self) -> Option<bool> {
        match self {
            Self::Call { does_return, .. } => *does_return,
            _ => None,
        }
    }

    pub fn return_expression(&self) -> Option<&SemanticExpression> {
        match self {
            Self::Return { expression } => expression.as_ref(),
            _ => None,
        }
    }

    pub fn set_kind(&mut self, kind: SemanticTerminatorKind) {
        *self = default_terminator_for_kind(kind);
    }

    pub fn set_condition(&mut self, condition: SemanticExpression) -> Result<(), &'static str> {
        match self {
            Self::Branch {
                condition: current, ..
            } => {
                *current = condition;
                Ok(())
            }
            _ => Err("terminator condition is only valid for branch terminators"),
        }
    }

    pub fn set_true_target(&mut self, target: SemanticExpression) -> Result<(), &'static str> {
        match self {
            Self::Branch {
                true_target: current,
                ..
            } => {
                *current = target;
                Ok(())
            }
            _ => Err("terminator true_target is only valid for branch terminators"),
        }
    }

    pub fn set_false_target(&mut self, target: SemanticExpression) -> Result<(), &'static str> {
        match self {
            Self::Branch {
                false_target: current,
                ..
            } => {
                *current = target;
                Ok(())
            }
            _ => Err("terminator false_target is only valid for branch terminators"),
        }
    }

    pub fn set_target(&mut self, target: SemanticExpression) -> Result<(), &'static str> {
        match self {
            Self::Jump { target: current } | Self::Call { target: current, .. } => {
                *current = target;
                Ok(())
            }
            _ => Err("terminator target is only valid for jump and call terminators"),
        }
    }

    pub fn set_return_target(
        &mut self,
        return_target: Option<SemanticExpression>,
    ) -> Result<(), &'static str> {
        match self {
            Self::Call {
                return_target: current,
                ..
            } => {
                *current = return_target;
                Ok(())
            }
            _ => Err("terminator return_target is only valid for call terminators"),
        }
    }

    pub fn set_does_return(&mut self, does_return: Option<bool>) -> Result<(), &'static str> {
        match self {
            Self::Call {
                does_return: current,
                ..
            } => {
                *current = does_return;
                Ok(())
            }
            _ => Err("terminator does_return is only valid for call terminators"),
        }
    }

    pub fn set_return_expression(
        &mut self,
        expression: Option<SemanticExpression>,
    ) -> Result<(), &'static str> {
        match self {
            Self::Return {
                expression: current,
            } => {
                *current = expression;
                Ok(())
            }
            _ => Err("terminator expression is only valid for return terminators"),
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

    pub fn set_kind(&mut self, kind: SemanticExpressionKind) {
        *self = default_expression_for_kind(kind, self.bits());
    }

    pub fn set_operation(&mut self, operation: SemanticOperation) -> Result<(), &'static str> {
        match (self, operation) {
            (Self::Binary { op, .. }, SemanticOperation::Binary(value)) => *op = value,
            (Self::Unary { op, .. }, SemanticOperation::Unary(value)) => *op = value,
            (Self::Cast { op, .. }, SemanticOperation::Cast(value)) => *op = value,
            (Self::Compare { op, .. }, SemanticOperation::Compare(value)) => *op = value,
            _ => return Err("expression operation does not match expression kind"),
        }
        Ok(())
    }

    pub fn set_bits(&mut self, bits: u16) {
        match self {
            Self::Const { bits: current, .. }
            | Self::Load { bits: current, .. }
            | Self::Unary { bits: current, .. }
            | Self::Binary { bits: current, .. }
            | Self::Cast { bits: current, .. }
            | Self::Compare { bits: current, .. }
            | Self::Select { bits: current, .. }
            | Self::Extract { bits: current, .. }
            | Self::Concat { bits: current, .. }
            | Self::Undefined { bits: current }
            | Self::Poison { bits: current }
            | Self::Architecture { bits: current, .. }
            | Self::Intrinsic { bits: current, .. } => *current = bits,
            Self::Read(location) => location.set_bits(bits),
        }
    }

    pub fn set_left(&mut self, expression: SemanticExpression) -> Result<(), &'static str> {
        match self {
            Self::Binary { left, .. } | Self::Compare { left, .. } => {
                *left = Box::new(expression);
                Ok(())
            }
            _ => Err("expression left operand is not valid for this expression kind"),
        }
    }

    pub fn set_right(&mut self, expression: SemanticExpression) -> Result<(), &'static str> {
        match self {
            Self::Binary { right, .. } | Self::Compare { right, .. } => {
                *right = Box::new(expression);
                Ok(())
            }
            _ => Err("expression right operand is not valid for this expression kind"),
        }
    }

    pub fn set_argument(&mut self, expression: SemanticExpression) -> Result<(), &'static str> {
        match self {
            Self::Unary { arg, .. } | Self::Cast { arg, .. } | Self::Extract { arg, .. } => {
                *arg = Box::new(expression);
                Ok(())
            }
            _ => Err("expression argument is not valid for this expression kind"),
        }
    }

    pub fn set_condition(&mut self, expression: SemanticExpression) -> Result<(), &'static str> {
        match self {
            Self::Select {
                condition: current,
                ..
            } => {
                *current = Box::new(expression);
                Ok(())
            }
            _ => Err("expression condition is not valid for this expression kind"),
        }
    }

    pub fn set_when_true(&mut self, expression: SemanticExpression) -> Result<(), &'static str> {
        match self {
            Self::Select {
                when_true: current,
                ..
            } => {
                *current = Box::new(expression);
                Ok(())
            }
            _ => Err("expression when_true is not valid for this expression kind"),
        }
    }

    pub fn set_when_false(&mut self, expression: SemanticExpression) -> Result<(), &'static str> {
        match self {
            Self::Select {
                when_false: current,
                ..
            } => {
                *current = Box::new(expression);
                Ok(())
            }
            _ => Err("expression when_false is not valid for this expression kind"),
        }
    }

    pub fn set_address(&mut self, expression: SemanticExpression) -> Result<(), &'static str> {
        match self {
            Self::Load { addr, .. } => {
                *addr = Box::new(expression);
                Ok(())
            }
            _ => Err("expression address is only valid for load expressions"),
        }
    }

    pub fn set_address_space(
        &mut self,
        space: SemanticAddressSpace,
    ) -> Result<(), &'static str> {
        match self {
            Self::Load { space: current, .. } => {
                *current = space;
                Ok(())
            }
            _ => Err("expression address_space is only valid for load expressions"),
        }
    }

    pub fn set_location(&mut self, location: SemanticLocation) -> Result<(), &'static str> {
        match self {
            Self::Read(current) => {
                *current = Box::new(location);
                Ok(())
            }
            _ => Err("expression location is only valid for read expressions"),
        }
    }

    pub fn set_offset(&mut self, offset: u16) -> Result<(), &'static str> {
        match self {
            Self::Extract { lsb, .. } => {
                *lsb = offset;
                Ok(())
            }
            _ => Err("expression offset is only valid for extract expressions"),
        }
    }

    pub fn set_parts(&mut self, parts: Vec<SemanticExpression>) -> Result<(), &'static str> {
        match self {
            Self::Concat { parts: current, .. } => {
                *current = parts;
                Ok(())
            }
            _ => Err("expression parts are only valid for concat expressions"),
        }
    }

    pub fn set_name(&mut self, name: impl Into<String>) -> Result<(), &'static str> {
        match self {
            Self::Architecture { name: current, .. } | Self::Intrinsic { name: current, .. } => {
                *current = name.into();
                Ok(())
            }
            _ => Err("expression name is only valid for architecture and intrinsic expressions"),
        }
    }

    pub fn set_arguments(
        &mut self,
        arguments: Vec<SemanticExpression>,
    ) -> Result<(), &'static str> {
        match self {
            Self::Architecture { args, .. } | Self::Intrinsic { args, .. } => {
                *args = arguments;
                Ok(())
            }
            _ => {
                Err("expression arguments are only valid for architecture and intrinsic expressions")
            }
        }
    }

    pub fn set_value(&mut self, value: u128) -> Result<(), &'static str> {
        match self {
            Self::Const { value: current, .. } => {
                *current = value;
                Ok(())
            }
            _ => Err("expression value is only valid for const expressions"),
        }
    }
}

impl SemanticTemporary {
    pub fn set_id(&mut self, id: u32) {
        self.id = id;
    }

    pub fn set_bits(&mut self, bits: u16) {
        self.bits = bits;
    }

    pub fn set_name(&mut self, name: Option<String>) {
        self.name = name;
    }
}

impl SemanticDiagnostic {
    pub fn set_kind(&mut self, kind: SemanticDiagnosticKind) {
        self.kind = kind;
    }

    pub fn set_message(&mut self, message: String) {
        self.message = message;
    }
}

fn default_const(bits: u16) -> SemanticExpression {
    SemanticExpression::Const { value: 0, bits }
}

fn default_location_for_kind(kind: SemanticLocationKind, bits: u16) -> SemanticLocation {
    match kind {
        SemanticLocationKind::Register => SemanticLocation::Register {
            name: "reg".to_string(),
            bits,
        },
        SemanticLocationKind::Flag => SemanticLocation::Flag {
            name: "flag".to_string(),
            bits,
        },
        SemanticLocationKind::ProgramCounter => SemanticLocation::ProgramCounter { bits },
        SemanticLocationKind::Temporary => SemanticLocation::Temporary { id: 0, bits },
        SemanticLocationKind::Memory => SemanticLocation::Memory {
            space: SemanticAddressSpace::Default,
            addr: Box::new(default_const(64)),
            bits,
        },
    }
}

fn default_expression_for_kind(kind: SemanticExpressionKind, bits: u16) -> SemanticExpression {
    match kind {
        SemanticExpressionKind::Const => SemanticExpression::Const { value: 0, bits },
        SemanticExpressionKind::Read => {
            SemanticExpression::Read(Box::new(default_location_for_kind(SemanticLocationKind::Temporary, bits)))
        }
        SemanticExpressionKind::Load => SemanticExpression::Load {
            space: SemanticAddressSpace::Default,
            addr: Box::new(default_const(64)),
            bits,
        },
        SemanticExpressionKind::Unary => SemanticExpression::Unary {
            op: SemanticOperationUnary::Not,
            arg: Box::new(default_const(bits)),
            bits,
        },
        SemanticExpressionKind::Binary => SemanticExpression::Binary {
            op: SemanticOperationBinary::Add,
            left: Box::new(default_const(bits)),
            right: Box::new(default_const(bits)),
            bits,
        },
        SemanticExpressionKind::Cast => SemanticExpression::Cast {
            op: SemanticOperationCast::Bitcast,
            arg: Box::new(default_const(bits)),
            bits,
        },
        SemanticExpressionKind::Compare => SemanticExpression::Compare {
            op: SemanticOperationCompare::Eq,
            left: Box::new(default_const(bits)),
            right: Box::new(default_const(bits)),
            bits,
        },
        SemanticExpressionKind::Select => SemanticExpression::Select {
            condition: Box::new(default_const(1)),
            when_true: Box::new(default_const(bits)),
            when_false: Box::new(default_const(bits)),
            bits,
        },
        SemanticExpressionKind::Extract => SemanticExpression::Extract {
            arg: Box::new(default_const(bits)),
            lsb: 0,
            bits,
        },
        SemanticExpressionKind::Concat => SemanticExpression::Concat {
            parts: vec![default_const(bits)],
            bits,
        },
        SemanticExpressionKind::Undefined => SemanticExpression::Undefined { bits },
        SemanticExpressionKind::Poison => SemanticExpression::Poison { bits },
        SemanticExpressionKind::Architecture => SemanticExpression::Architecture {
            name: String::new(),
            args: Vec::new(),
            bits,
        },
        SemanticExpressionKind::Intrinsic => SemanticExpression::Intrinsic {
            name: String::new(),
            args: Vec::new(),
            bits,
        },
    }
}

fn default_effect_for_kind(kind: SemanticEffectKind) -> SemanticEffect {
    match kind {
        SemanticEffectKind::Set => SemanticEffect::Set {
            dst: default_location_for_kind(SemanticLocationKind::Temporary, 64),
            expression: default_const(64),
        },
        SemanticEffectKind::Store => SemanticEffect::Store {
            space: SemanticAddressSpace::Default,
            addr: default_const(64),
            expression: default_const(8),
            bits: 8,
        },
        SemanticEffectKind::MemorySet => SemanticEffect::MemorySet {
            space: SemanticAddressSpace::Default,
            addr: default_const(64),
            value: default_const(8),
            count: default_const(64),
            element_bits: 8,
            decrement: default_const(1),
        },
        SemanticEffectKind::MemoryCopy => SemanticEffect::MemoryCopy {
            src_space: SemanticAddressSpace::Default,
            src_addr: default_const(64),
            dst_space: SemanticAddressSpace::Default,
            dst_addr: default_const(64),
            count: default_const(64),
            element_bits: 8,
            decrement: default_const(1),
        },
        SemanticEffectKind::AtomicCmpXchg => SemanticEffect::AtomicCmpXchg {
            space: SemanticAddressSpace::Default,
            addr: default_const(64),
            expected: default_const(8),
            desired: default_const(8),
            bits: 8,
            observed: default_location_for_kind(SemanticLocationKind::Temporary, 8),
        },
        SemanticEffectKind::Fence => SemanticEffect::Fence {
            kind: SemanticFenceKind::SequentiallyConsistent,
        },
        SemanticEffectKind::Trap => SemanticEffect::Trap {
            kind: SemanticTrapKind::Breakpoint,
        },
        SemanticEffectKind::Architecture => SemanticEffect::Architecture {
            name: String::new(),
            args: Vec::new(),
            outputs: Vec::new(),
        },
        SemanticEffectKind::Intrinsic => SemanticEffect::Intrinsic {
            name: String::new(),
            args: Vec::new(),
            outputs: Vec::new(),
        },
        SemanticEffectKind::Nop => SemanticEffect::Nop,
    }
}

fn default_terminator_for_kind(kind: SemanticTerminatorKind) -> SemanticTerminator {
    match kind {
        SemanticTerminatorKind::FallThrough => SemanticTerminator::FallThrough,
        SemanticTerminatorKind::Jump => SemanticTerminator::Jump {
            target: default_const(64),
        },
        SemanticTerminatorKind::Branch => SemanticTerminator::Branch {
            condition: default_const(1),
            true_target: default_const(64),
            false_target: default_const(64),
        },
        SemanticTerminatorKind::Call => SemanticTerminator::Call {
            target: default_const(64),
            return_target: None,
            does_return: None,
        },
        SemanticTerminatorKind::Return => SemanticTerminator::Return { expression: None },
        SemanticTerminatorKind::Unreachable => SemanticTerminator::Unreachable,
        SemanticTerminatorKind::Trap => SemanticTerminator::Trap,
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
