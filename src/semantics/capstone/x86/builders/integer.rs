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
    InstructionSemantics, SemanticEffect, SemanticExpression, SemanticOperationBinary,
    SemanticOperationCast, SemanticOperationCompare, SemanticOperationUnary, SemanticTemporary,
    SemanticTerminator,
};
use capstone::Insn;
use capstone::InsnId;
use capstone::arch::ArchOperand;
use capstone::arch::x86::{X86Insn, X86Reg};

use super::common;

#[path = "integer/arithmetic.rs"]
mod arithmetic;
#[path = "integer/data_movement.rs"]
mod data_movement;
#[path = "integer/misc.rs"]
mod misc;
#[path = "integer/multiply_divide.rs"]
mod multiply_divide;

pub fn build(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    if matches!(instruction.mnemonic().unwrap_or_default(), "lock cmpxchg8b") {
        return data_movement::lock_cmpxchg8b(machine, operands);
    }
    if matches!(
        instruction.mnemonic().unwrap_or_default(),
        "lock cmpxchg16b"
    ) {
        return data_movement::lock_cmpxchg16b(machine, operands);
    }

    match instruction.id() {
        InsnId(id)
            if [
                X86Insn::X86_INS_AAA as u32,
                X86Insn::X86_INS_AAD as u32,
                X86Insn::X86_INS_AAM as u32,
                X86Insn::X86_INS_AAS as u32,
                X86Insn::X86_INS_DAA as u32,
            ]
            .contains(&id) =>
        {
            misc::ascii_adjust(machine, instruction, operands)
        }
        InsnId(id) if id == X86Insn::X86_INS_NOP as u32 => Some(common::complete(
            SemanticTerminator::FallThrough,
            vec![SemanticEffect::Nop],
        )),
        InsnId(id) if id == X86Insn::X86_INS_MOV as u32 || id == X86Insn::X86_INS_MOVABS as u32 => {
            data_movement::assign(machine, operands)
        }
        InsnId(id) if id == X86Insn::X86_INS_MOVBE as u32 => data_movement::movbe(machine, operands),
        InsnId(id) if id == X86Insn::X86_INS_XCHG as u32 => data_movement::exchange(machine, operands),
        InsnId(id) if id == X86Insn::X86_INS_XADD as u32 => {
            data_movement::exchange_add(machine, operands)
        }
        InsnId(id) if id == X86Insn::X86_INS_CMPXCHG as u32 => {
            data_movement::compare_exchange(machine, operands)
        }
        InsnId(id) if id == X86Insn::X86_INS_CMPXCHG16B as u32 => {
            data_movement::lock_cmpxchg16b(machine, operands)
        }
        InsnId(id) if id == X86Insn::X86_INS_MOVZX as u32 => {
            data_movement::movx(machine, operands, false)
        }
        InsnId(id)
            if id == X86Insn::X86_INS_MOVSX as u32 || id == X86Insn::X86_INS_MOVSXD as u32 =>
        {
            data_movement::movx(machine, operands, true)
        }
        InsnId(id) if id == X86Insn::X86_INS_LEA as u32 => data_movement::lea(machine, operands),
        InsnId(id) if [X86Insn::X86_INS_ADD as u32, X86Insn::X86_INS_SUB as u32].contains(&id) => {
            arithmetic::binary(
                machine,
                operands,
                if id == X86Insn::X86_INS_ADD as u32 {
                    SemanticOperationBinary::Add
                } else {
                    SemanticOperationBinary::Sub
                },
            )
        }
        InsnId(id) if [X86Insn::X86_INS_INC as u32, X86Insn::X86_INS_DEC as u32].contains(&id) => {
            arithmetic::unary(
                machine,
                operands,
                if id == X86Insn::X86_INS_INC as u32 {
                    SemanticOperationBinary::Add
                } else {
                    SemanticOperationBinary::Sub
                },
            )
        }
        InsnId(id) if [X86Insn::X86_INS_NEG as u32, X86Insn::X86_INS_NOT as u32].contains(&id) => {
            arithmetic::unary_op(
                machine,
                instruction,
                operands,
                if id == X86Insn::X86_INS_NEG as u32 {
                    SemanticOperationUnary::Neg
                } else {
                    SemanticOperationUnary::Not
                },
            )
        }
        InsnId(id) if id == X86Insn::X86_INS_BSWAP as u32 => arithmetic::unary_op(
            machine,
            instruction,
            operands,
            SemanticOperationUnary::ByteSwap,
        ),
        InsnId(id) if id == X86Insn::X86_INS_POPCNT as u32 => arithmetic::popcnt(machine, operands),
        InsnId(id) if id == X86Insn::X86_INS_CRC32 as u32 => misc::crc32(machine, operands),
        InsnId(id) if id == X86Insn::X86_INS_CMP as u32 => arithmetic::cmp_like(machine, operands),
        InsnId(id) if id == X86Insn::X86_INS_SBB as u32 => arithmetic::sbb(machine, operands),
        InsnId(id) if id == X86Insn::X86_INS_ADC as u32 => arithmetic::adc(machine, operands),
        InsnId(id) if id == X86Insn::X86_INS_ADCX as u32 => {
            arithmetic::adcx_adox(machine, operands, true)
        }
        InsnId(id) if id == X86Insn::X86_INS_ADOX as u32 => {
            arithmetic::adcx_adox(machine, operands, false)
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_CBW as u32,
                X86Insn::X86_INS_CWDE as u32,
                X86Insn::X86_INS_CDQE as u32,
                X86Insn::X86_INS_CWD as u32,
                X86Insn::X86_INS_CDQ as u32,
                X86Insn::X86_INS_CQO as u32,
            ]
            .contains(&id) =>
        {
            misc::sign_extension(instruction)
        }
        InsnId(id) if id == X86Insn::X86_INS_IMUL as u32 => {
            multiply_divide::imul(machine, operands)
        }
        InsnId(id) if id == X86Insn::X86_INS_MUL as u32 => multiply_divide::mul(machine, operands),
        InsnId(id) if id == X86Insn::X86_INS_MULX as u32 => {
            multiply_divide::mulx(machine, operands)
        }
        InsnId(id) if id == X86Insn::X86_INS_DIV as u32 => {
            multiply_divide::div(machine, operands, false)
        }
        InsnId(id) if id == X86Insn::X86_INS_IDIV as u32 => {
            multiply_divide::div(machine, operands, true)
        }
        InsnId(id) if id == X86Insn::X86_INS_XLATB as u32 => misc::xlat(machine),
        _ => None,
    }
}
