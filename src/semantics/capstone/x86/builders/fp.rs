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
    InstructionSemantics, SemanticAddressSpace, SemanticEffect, SemanticExpression,
    SemanticLocation, SemanticOperationBinary, SemanticOperationCast, SemanticOperationCompare,
    SemanticTerminator,
};
use capstone::Insn;
use capstone::InsnId;
use capstone::arch::ArchOperand;
use capstone::arch::x86::{X86Insn, X86OperandType, X86Reg};

use super::common;

#[path = "fp/scalar.rs"]
mod scalar_helpers;
#[path = "fp/x87.rs"]
mod x87_helpers;

use scalar_helpers::*;
use x87_helpers::*;

pub fn build(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let mnemonic = instruction.mnemonic().unwrap_or_default();
    if matches!(
        mnemonic,
        "fld"
            | "fst"
            | "fstp"
            | "fist"
            | "fistp"
            | "fisttp"
            | "fbld"
            | "fbstp"
            | "fild"
            | "fldz"
            | "fld1"
            | "fldl2e"
            | "fldl2t"
            | "fldlg2"
            | "fldln2"
            | "fldpi"
            | "fadd"
            | "faddp"
            | "fiadd"
            | "fmul"
            | "fmulp"
            | "fdiv"
            | "fdivp"
            | "fdivr"
            | "fdivrp"
            | "fidiv"
            | "fidivr"
            | "fsub"
            | "fsubp"
            | "fsubr"
            | "fsubrp"
            | "fisub"
            | "fisubr"
            | "fcomp"
            | "fcom"
            | "fcomi"
            | "fcompi"
            | "fcomip"
            | "fcompp"
            | "fucom"
            | "fucomi"
            | "fucompi"
            | "fucomip"
            | "fucomp"
            | "fucompp"
            | "fnstsw"
            | "fninit"
            | "fabs"
            | "fchs"
            | "fxch"
            | "fnop"
            | "ffree"
            | "ffreep"
            | "fnclex"
            | "fcos"
            | "fsin"
            | "fsincos"
            | "fscale"
            | "fprem"
            | "fprem1"
            | "f2xm1"
            | "fptan"
            | "fpatan"
            | "fsqrt"
            | "fdecstp"
            | "fincstp"
            | "fxam"
            | "ftst"
            | "frndint"
            | "fyl2x"
            | "fyl2xp1"
    ) {
        return x87(machine, instruction, operands);
    }
    if mnemonic.starts_with("fcmov") {
        return x87(machine, instruction, operands);
    }
    if matches!(
        mnemonic,
        "cmpeqss"
            | "cmpltss"
            | "cmpless"
            | "cmpunordss"
            | "cmpneqss"
            | "cmpnltss"
            | "cmpnless"
            | "cmpordss"
            | "vcmpeqss"
            | "vcmpltss"
            | "vcmpless"
            | "vcmpunordss"
            | "vcmpneqss"
            | "vcmpnltss"
            | "vcmpnless"
            | "vcmpordss"
    ) {
        return scalar_ss(machine, instruction, operands);
    }

    match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_MOVSD as u32 => movsd(machine, operands),
        InsnId(id) if id == X86Insn::X86_INS_VMOVSD as u32 => vmovsd(machine, operands),
        InsnId(id)
            if [
                X86Insn::X86_INS_ADDSD as u32,
                X86Insn::X86_INS_MULSD as u32,
                X86Insn::X86_INS_DIVSD as u32,
                X86Insn::X86_INS_SUBSD as u32,
                X86Insn::X86_INS_MINSD as u32,
                X86Insn::X86_INS_MAXSD as u32,
                X86Insn::X86_INS_SQRTSD as u32,
            ]
            .contains(&id) =>
        {
            scalar_fp(machine, instruction, operands)
        }
        InsnId(id) if id == X86Insn::X86_INS_FIMUL as u32 => x87(machine, instruction, operands),
        InsnId(id)
            if [
                X86Insn::X86_INS_COMISD as u32,
                X86Insn::X86_INS_UCOMISD as u32,
                X86Insn::X86_INS_COMISS as u32,
                X86Insn::X86_INS_UCOMISS as u32,
                X86Insn::X86_INS_VCOMISD as u32,
                X86Insn::X86_INS_VCOMISS as u32,
                X86Insn::X86_INS_VUCOMISD as u32,
                X86Insn::X86_INS_VUCOMISS as u32,
            ]
            .contains(&id) =>
        {
            compare_fp(machine, instruction, operands)
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_CVTTSD2SI as u32,
                X86Insn::X86_INS_CVTSD2SI as u32,
                X86Insn::X86_INS_CVTSS2SI as u32,
                X86Insn::X86_INS_CVTTSS2SI as u32,
            ]
            .contains(&id) =>
        {
            scalar_convert(machine, instruction, operands)
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_CVTDQ2PD as u32,
                X86Insn::X86_INS_CVTDQ2PS as u32,
                X86Insn::X86_INS_CVTPD2DQ as u32,
                X86Insn::X86_INS_CVTPD2PS as u32,
                X86Insn::X86_INS_CVTPI2PD as u32,
                X86Insn::X86_INS_CVTPI2PS as u32,
                X86Insn::X86_INS_CVTPS2DQ as u32,
                X86Insn::X86_INS_CVTPS2PD as u32,
                X86Insn::X86_INS_CVTSD2SS as u32,
                X86Insn::X86_INS_CVTSI2SD as u32,
                X86Insn::X86_INS_CVTSI2SS as u32,
                X86Insn::X86_INS_CVTSS2SD as u32,
                X86Insn::X86_INS_CVTTPD2DQ as u32,
                X86Insn::X86_INS_CVTTPS2DQ as u32,
            ]
            .contains(&id) =>
        {
            packed_convert(machine, instruction, operands)
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_ADDSUBPD as u32,
                X86Insn::X86_INS_ADDSUBPS as u32,
                X86Insn::X86_INS_ADDPD as u32,
                X86Insn::X86_INS_ADDPS as u32,
                X86Insn::X86_INS_DIVPD as u32,
                X86Insn::X86_INS_DIVPS as u32,
                X86Insn::X86_INS_HADDPD as u32,
                X86Insn::X86_INS_MULPD as u32,
                X86Insn::X86_INS_MULPS as u32,
                X86Insn::X86_INS_SUBPD as u32,
                X86Insn::X86_INS_SUBPS as u32,
                X86Insn::X86_INS_HADDPS as u32,
                X86Insn::X86_INS_SQRTPD as u32,
                X86Insn::X86_INS_MAXPS as u32,
                X86Insn::X86_INS_MINPS as u32,
                X86Insn::X86_INS_SHUFPD as u32,
                X86Insn::X86_INS_SHUFPS as u32,
                X86Insn::X86_INS_VADDSUBPD as u32,
                X86Insn::X86_INS_VADDSUBPS as u32,
                X86Insn::X86_INS_VHADDPD as u32,
                X86Insn::X86_INS_VHADDPS as u32,
            ]
            .contains(&id) =>
        {
            packed_fp(machine, instruction, operands)
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_ADDSS as u32,
                X86Insn::X86_INS_SUBSS as u32,
                X86Insn::X86_INS_DIVSS as u32,
                X86Insn::X86_INS_MULSS as u32,
                X86Insn::X86_INS_SQRTSS as u32,
                X86Insn::X86_INS_MAXSS as u32,
                X86Insn::X86_INS_MINSS as u32,
                X86Insn::X86_INS_CMPSS as u32,
            ]
            .contains(&id) =>
        {
            scalar_ss(machine, instruction, operands)
        }
        InsnId(id)
            if [X86Insn::X86_INS_VFMADDSD as u32, X86Insn::X86_INS_VFMSUBSD as u32]
                .contains(&id) =>
        {
            scalar_vfma(machine, instruction, operands)
        }
        InsnId(id) if id == X86Insn::X86_INS_PCMPISTRI as u32 => {
            pcmpistri(machine, operands)
        }
        _ => None,
    }
}

fn low_64(expression: SemanticExpression) -> SemanticExpression {
    SemanticExpression::Extract {
        arg: Box::new(expression),
        lsb: 0,
        bits: 64,
    }
}

fn low_32(expression: SemanticExpression) -> SemanticExpression {
    SemanticExpression::Extract {
        arg: Box::new(expression),
        lsb: 0,
        bits: 32,
    }
}
