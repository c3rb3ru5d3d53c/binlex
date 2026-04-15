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

use crate::disassemblers::cil::Instruction;
use crate::disassemblers::cil::Mnemonic;
use crate::semantics::{
    InstructionSemantics, SemanticDiagnostic, SemanticDiagnosticKind, SemanticEffect,
    SemanticExpression, SemanticStatus, SemanticTerminator, SemanticTrapKind,
};

pub fn build(instruction: &Instruction<'_>) -> InstructionSemantics {
    if instruction.is_return() {
        return InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            temporaries: Vec::new(),
            effects: Vec::new(),
            terminator: if matches!(instruction.mnemonic, Mnemonic::Throw) {
                SemanticTerminator::Trap
            } else {
                SemanticTerminator::Return { expression: None }
            },
            diagnostics: Vec::new(),
        };
    }

    if instruction.is_call() {
        return InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Intrinsic {
                name: format!("cil.{:?}", instruction.mnemonic),
                args: operand_args(instruction),
                outputs: Vec::new(),
            }],
            terminator: SemanticTerminator::Call {
                target: SemanticExpression::Intrinsic {
                    name: format!("cil.{:?}.target", instruction.mnemonic),
                    args: operand_args(instruction),
                    bits: 64,
                },
                return_target: instruction.next().map(|next| SemanticExpression::Const {
                    value: next as u128,
                    bits: 64,
                }),
                does_return: Some(true),
            },
            diagnostics: Vec::new(),
        };
    }

    if instruction.is_conditional_jump() {
        let true_target = instruction.to().iter().next().copied().unwrap_or_default();
        return InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Intrinsic {
                name: format!("cil.{:?}", instruction.mnemonic),
                args: operand_args(instruction),
                outputs: Vec::new(),
            }],
            terminator: SemanticTerminator::Branch {
                condition: SemanticExpression::Intrinsic {
                    name: format!("cil.{:?}.cond", instruction.mnemonic),
                    args: operand_args(instruction),
                    bits: 1,
                },
                true_target: SemanticExpression::Const {
                    value: true_target as u128,
                    bits: 64,
                },
                false_target: SemanticExpression::Const {
                    value: instruction.next().unwrap_or(instruction.address) as u128,
                    bits: 64,
                },
            },
            diagnostics: Vec::new(),
        };
    }

    if instruction.is_jump() || instruction.is_switch() {
        let target = instruction.to().iter().next().copied().unwrap_or_default();
        return InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            temporaries: Vec::new(),
            effects: Vec::new(),
            terminator: SemanticTerminator::Jump {
                target: SemanticExpression::Const {
                    value: target as u128,
                    bits: 64,
                },
            },
            diagnostics: Vec::new(),
        };
    }

    match instruction.mnemonic {
        Mnemonic::Nop => InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Nop],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        },
        Mnemonic::Break => InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Trap {
                kind: SemanticTrapKind::Breakpoint,
            }],
            terminator: SemanticTerminator::Trap,
            diagnostics: Vec::new(),
        },
        mnemonic
            if matches!(
                mnemonic,
                Mnemonic::LdNull
                    | Mnemonic::DUP
                    | Mnemonic::Pop
                    | Mnemonic::Add
                    | Mnemonic::AddOvf
                    | Mnemonic::AddOvfUn
                    | Mnemonic::And
                    | Mnemonic::Div
                    | Mnemonic::DivUn
                    | Mnemonic::Mul
                    | Mnemonic::MulOvf
                    | Mnemonic::MulOvfUn
                    | Mnemonic::Neg
                    | Mnemonic::Not
                    | Mnemonic::Or
                    | Mnemonic::Rem
                    | Mnemonic::RemUn
                    | Mnemonic::Shl
                    | Mnemonic::Shr
                    | Mnemonic::ShrUn
                    | Mnemonic::Sub
                    | Mnemonic::SubOvf
                    | Mnemonic::SubOvfUn
                    | Mnemonic::Xor
                    | Mnemonic::Ceq
                    | Mnemonic::Cgt
                    | Mnemonic::CgtUn
                    | Mnemonic::Clt
                    | Mnemonic::CltUn
                    | Mnemonic::ConvI
                    | Mnemonic::ConvI1
                    | Mnemonic::ConvI2
                    | Mnemonic::ConvI4
                    | Mnemonic::ConvI8
                    | Mnemonic::ConvOvfI
                    | Mnemonic::ConvOvfIUn
                    | Mnemonic::ConvOvfI1
                    | Mnemonic::ConvOvfI1Un
                    | Mnemonic::ConvOvfI2
                    | Mnemonic::ConvOvfI2Un
                    | Mnemonic::ConvOvfI4
                    | Mnemonic::ConvOvfI4Un
                    | Mnemonic::ConvOvfI8
                    | Mnemonic::ConvOvfI8Un
                    | Mnemonic::ConvOvfU
                    | Mnemonic::ConvOvfUUn
                    | Mnemonic::ConvOvfU1
                    | Mnemonic::ConvOvfU1Un
                    | Mnemonic::ConvOvfU2
                    | Mnemonic::ConvOvfU2Un
                    | Mnemonic::ConvOvfU4
                    | Mnemonic::ConvOvfU4Un
                    | Mnemonic::ConvOvfU8
                    | Mnemonic::ConvOvfU8Un
                    | Mnemonic::ConvRUn
                    | Mnemonic::ConvR4
                    | Mnemonic::ConvR8
                    | Mnemonic::ConvU
                    | Mnemonic::ConvU1
                    | Mnemonic::ConvU2
                    | Mnemonic::ConvU4
                    | Mnemonic::ConvU8
                    | Mnemonic::LdcI4
                    | Mnemonic::LdcI40
                    | Mnemonic::LdcI41
                    | Mnemonic::LdcI42
                    | Mnemonic::LdcI43
                    | Mnemonic::LdcI44
                    | Mnemonic::LdcI45
                    | Mnemonic::LdcI46
                    | Mnemonic::LdcI47
                    | Mnemonic::LdcI48
                    | Mnemonic::LdcI4M1
                    | Mnemonic::LdcI4S
                    | Mnemonic::LdcI8
                    | Mnemonic::LdcR4
                    | Mnemonic::LdcR8
                    | Mnemonic::LdArg0
                    | Mnemonic::LdArg1
                    | Mnemonic::LdArg2
                    | Mnemonic::LdArg3
                    | Mnemonic::LdArgS
                    | Mnemonic::LdArg
                    | Mnemonic::LdArgA
                    | Mnemonic::LdArgAS
                    | Mnemonic::LdLoc0
                    | Mnemonic::LdLoc1
                    | Mnemonic::LdLoc2
                    | Mnemonic::LdLoc3
                    | Mnemonic::LdLocS
                    | Mnemonic::LdLoc
                    | Mnemonic::LdLocA
                    | Mnemonic::LdLocAS
                    | Mnemonic::StLoc0
                    | Mnemonic::StLoc1
                    | Mnemonic::StLoc2
                    | Mnemonic::StLoc3
                    | Mnemonic::StLocS
                    | Mnemonic::SLoc
                    | Mnemonic::StArg
                    | Mnemonic::StArgS
                    | Mnemonic::Box
                    | Mnemonic::CastClass
                    | Mnemonic::CkInite
                    | Mnemonic::Constrained
                    | Mnemonic::CpBlk
                    | Mnemonic::Cpobj
                    | Mnemonic::End
                    | Mnemonic::EndFilter
                    | Mnemonic::InitBlk
                    | Mnemonic::InitObj
                    | Mnemonic::IsInst
                    | Mnemonic::Jmp
                    | Mnemonic::LdElm
                    | Mnemonic::LdElmI
                    | Mnemonic::LdElmI1
                    | Mnemonic::LdElmI2
                    | Mnemonic::LdElmI4
                    | Mnemonic::LdElmU8
                    | Mnemonic::LdElmR4
                    | Mnemonic::LdElmR8
                    | Mnemonic::LdElmRef
                    | Mnemonic::LdElmU1
                    | Mnemonic::LdElmU2
                    | Mnemonic::LdElmU4
                    | Mnemonic::LdElmA
                    | Mnemonic::LdFld
                    | Mnemonic::LdFldA
                    | Mnemonic::LdFtn
                    | Mnemonic::LdIndI
                    | Mnemonic::LdIndI1
                    | Mnemonic::LdIndI2
                    | Mnemonic::LdIndI4
                    | Mnemonic::LdIndU8
                    | Mnemonic::LdIndR4
                    | Mnemonic::LdIndR8
                    | Mnemonic::LdIndRef
                    | Mnemonic::LdIndU1
                    | Mnemonic::LdIndU2
                    | Mnemonic::LdIndU4
                    | Mnemonic::LdLen
                    | Mnemonic::LdObj
                    | Mnemonic::LdSFld
                    | Mnemonic::LdSFldA
                    | Mnemonic::LdStr
                    | Mnemonic::LdToken
                    | Mnemonic::LdVirtFtn
                    | Mnemonic::Leave
                    | Mnemonic::LeaveS
                    | Mnemonic::LocAlloc
                    | Mnemonic::MkRefAny
                    | Mnemonic::NewArr
                    | Mnemonic::NewObj
                    | Mnemonic::No
                    | Mnemonic::ReadOnly
                    | Mnemonic::RefAnyType
                    | Mnemonic::RefAnyVal
                    | Mnemonic::ReThrow
                    | Mnemonic::SizeOf
                    | Mnemonic::StElem
                    | Mnemonic::StElemI
                    | Mnemonic::StElemI1
                    | Mnemonic::StElemI2
                    | Mnemonic::StElemI4
                    | Mnemonic::StElemI8
                    | Mnemonic::StElemR4
                    | Mnemonic::StElemR8
                    | Mnemonic::StElemREF
                    | Mnemonic::StFld
                    | Mnemonic::StIndI
                    | Mnemonic::StIndI1
                    | Mnemonic::StIndI2
                    | Mnemonic::StIndI4
                    | Mnemonic::StIndI8
                    | Mnemonic::StIndR4
                    | Mnemonic::StIndR8
                    | Mnemonic::StIndRef
                    | Mnemonic::StObj
                    | Mnemonic::StSFld
                    | Mnemonic::Tail
                    | Mnemonic::Unaligned
                    | Mnemonic::Unbox
                    | Mnemonic::UnboxAny
                    | Mnemonic::Volatile
            ) =>
        {
            complete_intrinsic(instruction, format!("cil.{:?}", mnemonic))
        }
        _ => InstructionSemantics {
            version: 1,
            status: SemanticStatus::Partial,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Intrinsic {
                name: format!("cil.{:?}", instruction.mnemonic),
                args: Vec::new(),
                outputs: Vec::new(),
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: vec![diagnostic(
                SemanticDiagnosticKind::ArchSpecific {
                    name: "cil.stack".to_string(),
                },
                "CIL stack effects currently modeled as intrinsics",
            )],
        },
    }
}

fn complete_intrinsic(instruction: &Instruction<'_>, name: String) -> InstructionSemantics {
    InstructionSemantics {
        version: 1,
        status: SemanticStatus::Complete,
        temporaries: Vec::new(),
        effects: vec![SemanticEffect::Intrinsic {
            name,
            args: operand_args(instruction),
            outputs: Vec::new(),
        }],
        terminator: SemanticTerminator::FallThrough,
        diagnostics: Vec::new(),
    }
}

fn operand_args(instruction: &Instruction<'_>) -> Vec<SemanticExpression> {
    if instruction.operand_size() == 0 {
        return Vec::new();
    }
    vec![SemanticExpression::Const {
        value: operand_value(instruction) as u128,
        bits: (instruction.operand_size() * 8) as u16,
    }]
}

fn operand_value(instruction: &Instruction<'_>) -> u64 {
    let mut bytes = [0u8; 8];
    let operand = instruction.operand_bytes();
    let len = operand.len().min(bytes.len());
    bytes[..len].copy_from_slice(&operand[..len]);
    u64::from_le_bytes(bytes)
}

fn diagnostic(kind: SemanticDiagnosticKind, message: &str) -> SemanticDiagnostic {
    SemanticDiagnostic {
        kind,
        message: message.to_string(),
    }
}
