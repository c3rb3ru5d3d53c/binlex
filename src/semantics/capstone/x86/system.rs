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

extern crate capstone;

use crate::Architecture;
use crate::semantics::{
    InstructionSemantics, SemanticEffect, SemanticFenceKind, SemanticTerminator, SemanticTrapKind,
};
use capstone::Insn;
use capstone::InsnId;
use capstone::arch::ArchOperand;
use capstone::arch::x86::X86Insn;

use super::common;

pub fn build(
    _machine: Architecture,
    instruction: &Insn,
    _operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    if matches!(instruction.mnemonic().unwrap_or_default(), "pushfd") {
        return Some(common::complete(
            SemanticTerminator::FallThrough,
            vec![SemanticEffect::Intrinsic {
                name: "x86.pushfd".to_string(),
                args: Vec::new(),
                outputs: Vec::new(),
            }],
        ));
    }
    if matches!(instruction.mnemonic().unwrap_or_default(), "pause") {
        return Some(common::complete(
            SemanticTerminator::FallThrough,
            vec![SemanticEffect::Intrinsic {
                name: "x86.pause".to_string(),
                args: Vec::new(),
                outputs: Vec::new(),
            }],
        ));
    }

    if matches!(instruction.id(), InsnId(id) if id == X86Insn::X86_INS_LFENCE as u32) {
        return Some(common::complete(
            SemanticTerminator::FallThrough,
            vec![SemanticEffect::Fence {
                kind: SemanticFenceKind::Acquire,
            }],
        ));
    }
    if matches!(instruction.id(), InsnId(id) if id == X86Insn::X86_INS_CLI as u32) {
        return Some(common::complete(
            SemanticTerminator::FallThrough,
            vec![SemanticEffect::Intrinsic {
                name: "x86.cli".to_string(),
                args: Vec::new(),
                outputs: Vec::new(),
            }],
        ));
    }
    if matches!(instruction.id(), InsnId(id) if id == X86Insn::X86_INS_STI as u32) {
        return Some(common::complete(
            SemanticTerminator::FallThrough,
            vec![SemanticEffect::Intrinsic {
                name: "x86.sti".to_string(),
                args: Vec::new(),
                outputs: Vec::new(),
            }],
        ));
    }
    if matches!(instruction.id(), InsnId(id) if id == X86Insn::X86_INS_PUSHFQ as u32) {
        return Some(common::complete(
            SemanticTerminator::FallThrough,
            vec![SemanticEffect::Intrinsic {
                name: "x86.pushfq".to_string(),
                args: Vec::new(),
                outputs: Vec::new(),
            }],
        ));
    }
    if matches!(instruction.id(), InsnId(id) if id == X86Insn::X86_INS_POPFQ as u32) {
        return Some(common::complete(
            SemanticTerminator::FallThrough,
            vec![SemanticEffect::Intrinsic {
                name: "x86.popfq".to_string(),
                args: Vec::new(),
                outputs: Vec::new(),
            }],
        ));
    }
    if matches!(instruction.id(), InsnId(id) if id == X86Insn::X86_INS_INSD as u32) {
        return Some(common::complete(
            SemanticTerminator::FallThrough,
            vec![SemanticEffect::Intrinsic {
                name: "x86.insd".to_string(),
                args: Vec::new(),
                outputs: Vec::new(),
            }],
        ));
    }
    if matches!(instruction.id(), InsnId(id) if id == X86Insn::X86_INS_OUTSD as u32) {
        return Some(common::complete(
            SemanticTerminator::FallThrough,
            vec![SemanticEffect::Intrinsic {
                name: "x86.outsd".to_string(),
                args: Vec::new(),
                outputs: Vec::new(),
            }],
        ));
    }

    let trap = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_INT3 as u32 => Some(SemanticTrapKind::Breakpoint),
        InsnId(id) if id == X86Insn::X86_INS_INT as u32 => Some(SemanticTrapKind::Interrupt),
        InsnId(id) if id == X86Insn::X86_INS_UD2 as u32 => Some(SemanticTrapKind::InvalidOpcode),
        InsnId(id) if id == X86Insn::X86_INS_SYSCALL as u32 => Some(SemanticTrapKind::Syscall),
        _ => None,
    }?;

    Some(common::complete(
        if matches!(trap, SemanticTrapKind::Syscall) {
            SemanticTerminator::Trap
        } else {
            SemanticTerminator::Trap
        },
        vec![SemanticEffect::Trap { kind: trap }],
    ))
}
