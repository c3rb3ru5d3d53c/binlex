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
    SemanticFenceKind, SemanticOperationBinary, SemanticOperationCast, SemanticTerminator,
    SemanticTrapKind,
};
use capstone::Insn;
use capstone::InsnId;
use capstone::arch::ArchOperand;
use capstone::arch::x86::{X86Insn, X86Reg};

use super::common;

pub fn build(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let mnemonic = instruction.mnemonic().unwrap_or_default();
    if matches!(instruction.mnemonic().unwrap_or_default(), "pushfd") {
        return pushf(machine, 32);
    }
    if matches!(mnemonic, "popfd" | "popf") {
        return popf(machine, 32);
    }
    if matches!(mnemonic, "pause") {
        return Some(common::complete(
            SemanticTerminator::FallThrough,
            vec![SemanticEffect::Nop],
        ));
    }
    if matches!(
        mnemonic,
        "prefetch" | "prefetchnta" | "prefetcht0" | "prefetcht1" | "prefetcht2" | "prefetchw"
    ) {
        return Some(common::complete(
            SemanticTerminator::FallThrough,
            vec![SemanticEffect::Nop],
        ));
    }
    if matches!(mnemonic, "endbr32" | "endbr64" | "wait") {
        return Some(common::complete(
            SemanticTerminator::FallThrough,
            vec![SemanticEffect::Nop],
        ));
    }

    if matches!(instruction.id(), InsnId(id) if id == X86Insn::X86_INS_MFENCE as u32) {
        return Some(fence(SemanticFenceKind::SequentiallyConsistent));
    }
    if matches!(instruction.id(), InsnId(id) if id == X86Insn::X86_INS_SFENCE as u32) {
        return Some(fence(SemanticFenceKind::Release));
    }
    if matches!(instruction.id(), InsnId(id) if id == X86Insn::X86_INS_LFENCE as u32) {
        return Some(fence(SemanticFenceKind::Acquire));
    }
    if matches!(instruction.id(), InsnId(id) if id == X86Insn::X86_INS_CLFLUSH as u32) {
        return Some(fence(SemanticFenceKind::ArchSpecific {
            name: "x86.clflush".to_string(),
        }));
    }
    if matches!(instruction.id(), InsnId(id) if id == X86Insn::X86_INS_CLTS as u32) {
        return Some(clts());
    }
    if matches!(instruction.id(), InsnId(id) if id == X86Insn::X86_INS_INVD as u32) {
        return Some(fence(SemanticFenceKind::ArchSpecific {
            name: "x86.invd".to_string(),
        }));
    }
    if matches!(instruction.id(), InsnId(id) if id == X86Insn::X86_INS_INVLPG as u32) {
        return invlpg(machine, operands);
    }
    if matches!(instruction.id(), InsnId(id) if id == X86Insn::X86_INS_WBINVD as u32) {
        return Some(fence(SemanticFenceKind::ArchSpecific {
            name: "x86.wbinvd".to_string(),
        }));
    }
    if matches!(instruction.id(), InsnId(id) if id == X86Insn::X86_INS_CLC as u32) {
        return Some(set_flag("cf", false));
    }
    if matches!(instruction.id(), InsnId(id) if id == X86Insn::X86_INS_STC as u32) {
        return Some(set_flag("cf", true));
    }
    if matches!(instruction.id(), InsnId(id) if id == X86Insn::X86_INS_CMC as u32) {
        return Some(common::complete(
            SemanticTerminator::FallThrough,
            vec![SemanticEffect::Set {
                dst: common::flag("cf"),
                expression: SemanticExpression::Binary {
                    op: SemanticOperationBinary::Xor,
                    left: Box::new(common::flag_expr("cf")),
                    right: Box::new(common::bool_const(true)),
                    bits: 1,
                },
            }],
        ));
    }
    if matches!(instruction.id(), InsnId(id) if id == X86Insn::X86_INS_CLD as u32) {
        return Some(set_flag("df", false));
    }
    if matches!(instruction.id(), InsnId(id) if id == X86Insn::X86_INS_STD as u32) {
        return Some(set_flag("df", true));
    }
    if matches!(instruction.id(), InsnId(id) if id == X86Insn::X86_INS_LAHF as u32) {
        return Some(lahf());
    }
    if matches!(instruction.id(), InsnId(id) if id == X86Insn::X86_INS_SAHF as u32) {
        return Some(sahf());
    }
    if matches!(instruction.id(), InsnId(id) if id == X86Insn::X86_INS_CLI as u32) {
        return Some(set_flag("if", false));
    }
    if matches!(instruction.id(), InsnId(id) if id == X86Insn::X86_INS_STI as u32) {
        return Some(set_flag("if", true));
    }
    if matches!(
        instruction.id(),
        InsnId(id)
            if id == X86Insn::X86_INS_PUSHF as u32 || id == X86Insn::X86_INS_PUSHFD as u32
    ) {
        return pushf(machine, 32);
    }
    if matches!(instruction.id(), InsnId(id) if id == X86Insn::X86_INS_PUSHFQ as u32) {
        return pushf(machine, 64);
    }
    if matches!(
        instruction.id(),
        InsnId(id)
            if id == X86Insn::X86_INS_POPF as u32 || id == X86Insn::X86_INS_POPFD as u32
    ) {
        return popf(machine, 32);
    }
    if matches!(instruction.id(), InsnId(id) if id == X86Insn::X86_INS_POPFQ as u32) {
        return popf(machine, 64);
    }
    if matches!(instruction.id(), InsnId(id) if id == X86Insn::X86_INS_LDMXCSR as u32) {
        return ldmxcsr(machine, operands);
    }
    if matches!(instruction.id(), InsnId(id) if id == X86Insn::X86_INS_STMXCSR as u32) {
        return stmxcsr(machine, operands);
    }
    if matches!(
        instruction.id(),
        InsnId(id) if id == X86Insn::X86_INS_FXSAVE as u32
    ) {
        return fxsave(machine, operands, false);
    }
    if matches!(
        instruction.id(),
        InsnId(id) if id == X86Insn::X86_INS_FXSAVE64 as u32
    ) {
        return fxsave(machine, operands, true);
    }
    if matches!(
        instruction.id(),
        InsnId(id) if id == X86Insn::X86_INS_FXRSTOR as u32
    ) {
        return fxrstor(machine, operands, false);
    }
    if matches!(
        instruction.id(),
        InsnId(id) if id == X86Insn::X86_INS_FXRSTOR64 as u32
    ) {
        return fxrstor(machine, operands, true);
    }
    if matches!(instruction.id(), InsnId(id) if id == X86Insn::X86_INS_CPUID as u32) {
        return Some(cpuid());
    }
    if matches!(instruction.id(), InsnId(id) if id == X86Insn::X86_INS_VERR as u32) {
        return verr_verw(machine, operands, "x86.verr");
    }
    if matches!(instruction.id(), InsnId(id) if id == X86Insn::X86_INS_VERW as u32) {
        return verr_verw(machine, operands, "x86.verw");
    }
    if matches!(instruction.id(), InsnId(id) if id == X86Insn::X86_INS_INSD as u32) {
        return insd(machine);
    }
    if matches!(instruction.id(), InsnId(id) if id == X86Insn::X86_INS_OUTSD as u32) {
        return outsd(machine);
    }
    if matches!(instruction.id(), InsnId(id) if id == X86Insn::X86_INS_RDTSC as u32) {
        return Some(rdtsc());
    }
    if matches!(instruction.id(), InsnId(id) if id == X86Insn::X86_INS_RDTSCP as u32) {
        return Some(rdtscp());
    }
    if matches!(instruction.id(), InsnId(id) if id == X86Insn::X86_INS_RDRAND as u32) {
        return random_value(machine, "rdrand", operands);
    }
    if matches!(instruction.id(), InsnId(id) if id == X86Insn::X86_INS_RDSEED as u32) {
        return random_value(machine, "rdseed", operands);
    }

    let trap = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_INT3 as u32 => Some(SemanticTrapKind::Breakpoint),
        InsnId(id) if id == X86Insn::X86_INS_INT as u32 => Some(SemanticTrapKind::Interrupt),
        InsnId(id) if id == X86Insn::X86_INS_UD2 as u32 => Some(SemanticTrapKind::InvalidOpcode),
        InsnId(id) if id == X86Insn::X86_INS_SYSCALL as u32 => Some(SemanticTrapKind::Syscall),
        InsnId(id) if id == X86Insn::X86_INS_SYSENTER as u32 => {
            Some(SemanticTrapKind::ArchSpecific {
                name: "x86.sysenter".to_string(),
            })
        }
        _ => None,
    }?;

    Some(common::complete(
        SemanticTerminator::Trap,
        vec![SemanticEffect::Trap { kind: trap }],
    ))
}

fn fence(kind: SemanticFenceKind) -> InstructionSemantics {
    common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Fence { kind }],
    )
}

fn set_flag(name: &str, value: bool) -> InstructionSemantics {
    common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst: common::flag(name),
            expression: common::bool_const(value),
        }],
    )
}

fn clts() -> InstructionSemantics {
    common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Architecture {
            name: "x86.clts".to_string(),
            args: Vec::new(),
            outputs: Vec::new(),
        }],
    )
}

fn invlpg(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let addr = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Architecture {
            name: "x86.invlpg".to_string(),
            args: vec![addr],
            outputs: Vec::new(),
        }],
    ))
}

fn lahf() -> InstructionSemantics {
    common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst: common::reg(common::reg_id_name(X86Reg::X86_REG_AH as u16), 8),
            expression: flags_low_byte(),
        }],
    )
}

fn sahf() -> InstructionSemantics {
    let ah = SemanticExpression::Read(Box::new(common::reg(
        common::reg_id_name(X86Reg::X86_REG_AH as u16),
        8,
    )));
    common::complete(
        SemanticTerminator::FallThrough,
        vec![
            unpack_flag_from_byte("cf", ah.clone(), 0),
            unpack_flag_from_byte("pf", ah.clone(), 2),
            unpack_flag_from_byte("af", ah.clone(), 4),
            unpack_flag_from_byte("zf", ah.clone(), 6),
            unpack_flag_from_byte("sf", ah, 7),
        ],
    )
}

fn ldmxcsr(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let src = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst: mxcsr_location(),
            expression: src,
        }],
    ))
}

fn stmxcsr(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Read(Box::new(mxcsr_location())),
        }],
    ))
}

fn fxsave(
    machine: Architecture,
    operands: &[ArchOperand],
    wide_pointers: bool,
) -> Option<InstructionSemantics> {
    let base = memory_operand_addr(machine, operands.first()?)?;
    let pointer_bits = common::pointer_bits(machine);
    let mut effects = vec![
        store_default(base.clone(), 0, pointer_bits, read_reg("x87_fcw", 16), 16),
        store_default(base.clone(), 2, pointer_bits, x87_status_word_image(), 16),
        store_default(base.clone(), 4, pointer_bits, read_reg("x87_ftw", 8), 8),
        store_default(base.clone(), 5, pointer_bits, undefined(8), 8),
        store_default(base.clone(), 6, pointer_bits, read_reg("x87_fop", 16), 16),
    ];

    if wide_pointers {
        effects.push(store_default(
            base.clone(),
            8,
            pointer_bits,
            read_reg("x87_fip", 64),
            64,
        ));
        effects.push(store_default(
            base.clone(),
            16,
            pointer_bits,
            read_reg("x87_fdp", 64),
            64,
        ));
    } else {
        effects.push(store_default(
            base.clone(),
            8,
            pointer_bits,
            read_reg("x87_fip", 32),
            32,
        ));
        effects.push(store_default(
            base.clone(),
            12,
            pointer_bits,
            read_reg("x87_fcs", 16),
            16,
        ));
        effects.push(store_default(
            base.clone(),
            14,
            pointer_bits,
            undefined(16),
            16,
        ));
        effects.push(store_default(
            base.clone(),
            16,
            pointer_bits,
            read_reg("x87_fdp", 32),
            32,
        ));
        effects.push(store_default(
            base.clone(),
            20,
            pointer_bits,
            read_reg("x87_fds", 16),
            16,
        ));
        effects.push(store_default(
            base.clone(),
            22,
            pointer_bits,
            undefined(16),
            16,
        ));
    }

    effects.push(store_default(
        base.clone(),
        24,
        pointer_bits,
        SemanticExpression::Read(Box::new(mxcsr_location())),
        32,
    ));
    effects.push(store_default(
        base.clone(),
        28,
        pointer_bits,
        read_reg("mxcsr_mask", 32),
        32,
    ));

    for index in 0..8u64 {
        let offset = 32 + index * 16;
        effects.push(store_default(
            base.clone(),
            offset,
            pointer_bits,
            read_reg(&format!("x87_st{index}"), 80),
            80,
        ));
        effects.push(store_default(
            base.clone(),
            offset + 10,
            pointer_bits,
            undefined(48),
            48,
        ));
    }

    let xmm_count = if matches!(machine, Architecture::AMD64) {
        16
    } else {
        8
    };
    for index in 0..xmm_count {
        effects.push(store_default(
            base.clone(),
            160 + (index as u64) * 16,
            pointer_bits,
            read_reg(
                &common::reg_id_name(X86Reg::X86_REG_XMM0 as u16 + index as u16),
                128,
            ),
            128,
        ));
    }

    let used_tail = 160 + (xmm_count as u64) * 16;
    for offset in (used_tail..512).step_by(16) {
        let bits = ((512 - offset).min(16) * 8) as u16;
        effects.push(store_default(
            base.clone(),
            offset,
            pointer_bits,
            undefined(bits),
            bits,
        ));
    }

    Some(common::complete(SemanticTerminator::FallThrough, effects))
}

fn fxrstor(
    machine: Architecture,
    operands: &[ArchOperand],
    wide_pointers: bool,
) -> Option<InstructionSemantics> {
    let base = memory_operand_addr(machine, operands.first()?)?;
    let pointer_bits = common::pointer_bits(machine);
    let fsw = load_default(base.clone(), 2, pointer_bits, 16);
    let mut effects = vec![
        set_reg(
            "x87_fcw",
            16,
            load_default(base.clone(), 0, pointer_bits, 16),
        ),
        set_reg("x87_ftw", 8, load_default(base.clone(), 4, pointer_bits, 8)),
        set_reg(
            "x87_fop",
            16,
            load_default(base.clone(), 6, pointer_bits, 16),
        ),
        set_reg(
            "mxcsr_mask",
            32,
            load_default(base.clone(), 28, pointer_bits, 32),
        ),
        SemanticEffect::Set {
            dst: mxcsr_location(),
            expression: load_default(base.clone(), 24, pointer_bits, 32),
        },
        unpack_flag_from_word("x87_c0", fsw.clone(), 8),
        unpack_flag_from_word("x87_c1", fsw.clone(), 9),
        unpack_flag_from_word("x87_c2", fsw.clone(), 10),
        SemanticEffect::Set {
            dst: read_reg_location("x87_top", 3),
            expression: SemanticExpression::Extract {
                arg: Box::new(SemanticExpression::Binary {
                    op: SemanticOperationBinary::LShr,
                    left: Box::new(fsw.clone()),
                    right: Box::new(common::const_u64(11, 16)),
                    bits: 16,
                }),
                lsb: 0,
                bits: 3,
            },
        },
        unpack_flag_from_word("x87_c3", fsw, 14),
    ];

    if wide_pointers {
        effects.push(set_reg(
            "x87_fip",
            64,
            load_default(base.clone(), 8, pointer_bits, 64),
        ));
        effects.push(set_reg(
            "x87_fdp",
            64,
            load_default(base.clone(), 16, pointer_bits, 64),
        ));
    } else {
        effects.push(set_reg(
            "x87_fip",
            32,
            load_default(base.clone(), 8, pointer_bits, 32),
        ));
        effects.push(set_reg(
            "x87_fcs",
            16,
            load_default(base.clone(), 12, pointer_bits, 16),
        ));
        effects.push(set_reg(
            "x87_fdp",
            32,
            load_default(base.clone(), 16, pointer_bits, 32),
        ));
        effects.push(set_reg(
            "x87_fds",
            16,
            load_default(base.clone(), 20, pointer_bits, 16),
        ));
    }

    for index in 0..8u64 {
        let st = load_default(base.clone(), 32 + index * 16, pointer_bits, 80);
        let mm = SemanticExpression::Extract {
            arg: Box::new(st.clone()),
            lsb: 0,
            bits: 64,
        };
        effects.push(set_reg(&format!("x87_st{index}"), 80, st));
        effects.push(set_reg(
            &common::reg_id_name(X86Reg::X86_REG_MM0 as u16 + index as u16),
            64,
            mm,
        ));
    }

    let xmm_count = if matches!(machine, Architecture::AMD64) {
        16
    } else {
        8
    };
    for index in 0..xmm_count {
        effects.push(set_reg(
            &common::reg_id_name(X86Reg::X86_REG_XMM0 as u16 + index as u16),
            128,
            load_default(base.clone(), 160 + (index as u64) * 16, pointer_bits, 128),
        ));
    }

    Some(common::complete(SemanticTerminator::FallThrough, effects))
}

fn insd(machine: Architecture) -> Option<InstructionSemantics> {
    let di = string_index_location(machine, true);
    let port = io_port_location();
    let addr = SemanticExpression::Read(Box::new(di.clone()));
    let port_addr = SemanticExpression::Read(Box::new(port));
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Store {
                space: SemanticAddressSpace::Default,
                addr,
                expression: SemanticExpression::Load {
                    space: SemanticAddressSpace::Io,
                    addr: Box::new(port_addr),
                    bits: 32,
                },
                bits: 32,
            },
            SemanticEffect::Set {
                dst: di.clone(),
                expression: next_index_value(di, 4, machine),
            },
        ],
    ))
}

fn cpuid() -> InstructionSemantics {
    let leaf = SemanticExpression::Read(Box::new(common::reg(
        common::reg_id_name(X86Reg::X86_REG_EAX as u16),
        32,
    )));
    let subleaf = SemanticExpression::Read(Box::new(common::reg(
        common::reg_id_name(X86Reg::X86_REG_ECX as u16),
        32,
    )));

    common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Architecture {
            name: "x86.cpuid".to_string(),
            args: vec![leaf, subleaf],
            outputs: vec![
                common::reg(common::reg_id_name(X86Reg::X86_REG_EAX as u16), 32),
                common::reg(common::reg_id_name(X86Reg::X86_REG_EBX as u16), 32),
                common::reg(common::reg_id_name(X86Reg::X86_REG_ECX as u16), 32),
                common::reg(common::reg_id_name(X86Reg::X86_REG_EDX as u16), 32),
            ],
        }],
    )
}

fn verr_verw(
    machine: Architecture,
    operands: &[ArchOperand],
    name: &str,
) -> Option<InstructionSemantics> {
    let selector = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Architecture {
            name: name.to_string(),
            args: vec![selector],
            outputs: vec![common::flag("zf")],
        }],
    ))
}

fn outsd(machine: Architecture) -> Option<InstructionSemantics> {
    let si = string_index_location(machine, false);
    let port = io_port_location();
    let addr = SemanticExpression::Read(Box::new(si.clone()));
    let port_addr = SemanticExpression::Read(Box::new(port));
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Store {
                space: SemanticAddressSpace::Io,
                addr: port_addr,
                expression: SemanticExpression::Load {
                    space: SemanticAddressSpace::Default,
                    addr: Box::new(addr),
                    bits: 32,
                },
                bits: 32,
            },
            SemanticEffect::Set {
                dst: si.clone(),
                expression: next_index_value(si, 4, machine),
            },
        ],
    ))
}

fn rdtsc() -> InstructionSemantics {
    common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Architecture {
            name: "x86.rdtsc".to_string(),
            args: Vec::new(),
            outputs: vec![
                common::reg(common::reg_id_name(X86Reg::X86_REG_EAX as u16), 32),
                common::reg(common::reg_id_name(X86Reg::X86_REG_EDX as u16), 32),
            ],
        }],
    )
}

fn rdtscp() -> InstructionSemantics {
    common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Architecture {
            name: "x86.rdtscp".to_string(),
            args: Vec::new(),
            outputs: vec![
                common::reg(common::reg_id_name(X86Reg::X86_REG_EAX as u16), 32),
                common::reg(common::reg_id_name(X86Reg::X86_REG_EDX as u16), 32),
                common::reg(common::reg_id_name(X86Reg::X86_REG_ECX as u16), 32),
            ],
        }],
    )
}

fn random_value(
    machine: Architecture,
    name: &str,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let _bits = common::location_bits(&dst);
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Architecture {
                name: format!("x86.{name}"),
                args: Vec::new(),
                outputs: vec![dst, common::flag("cf")],
            },
            SemanticEffect::Set {
                dst: common::flag("of"),
                expression: common::bool_const(false),
            },
            SemanticEffect::Set {
                dst: common::flag("sf"),
                expression: common::bool_const(false),
            },
            SemanticEffect::Set {
                dst: common::flag("zf"),
                expression: common::bool_const(false),
            },
            SemanticEffect::Set {
                dst: common::flag("af"),
                expression: common::bool_const(false),
            },
            SemanticEffect::Set {
                dst: common::flag("pf"),
                expression: common::bool_const(false),
            },
        ],
    ))
}

fn pushf(machine: Architecture, bits: u16) -> Option<InstructionSemantics> {
    let stack_pointer = stack_pointer_location(machine);
    let pointer_bits = common::pointer_bits(machine);
    let slot_bytes = (bits / 8) as u64;
    let old_sp = SemanticExpression::Read(Box::new(stack_pointer.clone()));
    let new_sp = common::sub(
        old_sp,
        common::const_u64(slot_bytes, pointer_bits),
        pointer_bits,
    );
    let flags_value = flags_image(bits);
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst: stack_pointer.clone(),
                expression: new_sp.clone(),
            },
            SemanticEffect::Store {
                space: SemanticAddressSpace::Stack,
                addr: new_sp,
                expression: flags_value,
                bits,
            },
        ],
    ))
}

fn popf(machine: Architecture, bits: u16) -> Option<InstructionSemantics> {
    let stack_pointer = stack_pointer_location(machine);
    let pointer_bits = common::pointer_bits(machine);
    let slot_bytes = (bits / 8) as u64;
    let loaded = SemanticExpression::Load {
        space: SemanticAddressSpace::Stack,
        addr: Box::new(SemanticExpression::Read(Box::new(stack_pointer.clone()))),
        bits,
    };
    let mut effects = vec![
        unpack_flag_from_word("cf", loaded.clone(), 0),
        unpack_flag_from_word("pf", loaded.clone(), 2),
        unpack_flag_from_word("af", loaded.clone(), 4),
        unpack_flag_from_word("zf", loaded.clone(), 6),
        unpack_flag_from_word("sf", loaded.clone(), 7),
        unpack_flag_from_word("if", loaded.clone(), 9),
        unpack_flag_from_word("df", loaded.clone(), 10),
        unpack_flag_from_word("of", loaded.clone(), 11),
    ];
    effects.push(SemanticEffect::Set {
        dst: stack_pointer,
        expression: common::add(
            SemanticExpression::Read(Box::new(stack_pointer_location(machine))),
            common::const_u64(slot_bytes, pointer_bits),
            pointer_bits,
        ),
    });
    Some(common::complete(SemanticTerminator::FallThrough, effects))
}

fn flags_image(bits: u16) -> SemanticExpression {
    let mut value = common::const_u64(1 << 1, bits);
    for (name, bit) in [
        ("cf", 0),
        ("pf", 2),
        ("af", 4),
        ("zf", 6),
        ("sf", 7),
        ("if", 9),
        ("df", 10),
        ("of", 11),
    ] {
        let shifted = SemanticExpression::Binary {
            op: crate::semantics::SemanticOperationBinary::Shl,
            left: Box::new(SemanticExpression::Cast {
                op: SemanticOperationCast::ZeroExtend,
                arg: Box::new(common::flag_expr(name)),
                bits,
            }),
            right: Box::new(common::const_u64(bit as u64, bits)),
            bits,
        };
        value = common::or(value, shifted, bits);
    }
    value
}

fn flags_low_byte() -> SemanticExpression {
    let mut value = common::const_u64(1 << 1, 8);
    for (name, bit) in [("cf", 0), ("pf", 2), ("af", 4), ("zf", 6), ("sf", 7)] {
        let shifted = SemanticExpression::Binary {
            op: SemanticOperationBinary::Shl,
            left: Box::new(SemanticExpression::Cast {
                op: SemanticOperationCast::ZeroExtend,
                arg: Box::new(common::flag_expr(name)),
                bits: 8,
            }),
            right: Box::new(common::const_u64(bit as u64, 8)),
            bits: 8,
        };
        value = common::or(value, shifted, 8);
    }
    value
}

fn unpack_flag_from_word(name: &str, word: SemanticExpression, bit: u16) -> SemanticEffect {
    SemanticEffect::Set {
        dst: common::flag(name),
        expression: SemanticExpression::Extract {
            arg: Box::new(SemanticExpression::Binary {
                op: crate::semantics::SemanticOperationBinary::LShr,
                left: Box::new(word),
                right: Box::new(common::const_u64(bit as u64, 64)),
                bits: 64,
            }),
            lsb: 0,
            bits: 1,
        },
    }
}

fn unpack_flag_from_byte(name: &str, byte: SemanticExpression, bit: u16) -> SemanticEffect {
    SemanticEffect::Set {
        dst: common::flag(name),
        expression: SemanticExpression::Extract {
            arg: Box::new(SemanticExpression::Binary {
                op: SemanticOperationBinary::LShr,
                left: Box::new(byte),
                right: Box::new(common::const_u64(bit as u64, 8)),
                bits: 8,
            }),
            lsb: 0,
            bits: 1,
        },
    }
}

fn io_port_location() -> crate::semantics::SemanticLocation {
    common::reg(common::reg_id_name(X86Reg::X86_REG_DX as u16), 16)
}

fn read_reg_location(name: &str, bits: u16) -> crate::semantics::SemanticLocation {
    common::reg(name.to_string(), bits)
}

fn read_reg(name: &str, bits: u16) -> SemanticExpression {
    SemanticExpression::Read(Box::new(read_reg_location(name, bits)))
}

fn set_reg(name: &str, bits: u16, expression: SemanticExpression) -> SemanticEffect {
    SemanticEffect::Set {
        dst: read_reg_location(name, bits),
        expression,
    }
}

fn undefined(bits: u16) -> SemanticExpression {
    SemanticExpression::Undefined { bits }
}

fn memory_operand_addr(machine: Architecture, operand: &ArchOperand) -> Option<SemanticExpression> {
    match common::operand_location(machine, operand)? {
        crate::semantics::SemanticLocation::Memory { addr, .. } => Some(*addr),
        _ => None,
    }
}

fn addr_with_offset(
    base: SemanticExpression,
    offset: u64,
    pointer_bits: u16,
) -> SemanticExpression {
    if offset == 0 {
        base
    } else {
        common::add(base, common::const_u64(offset, pointer_bits), pointer_bits)
    }
}

fn store_default(
    base: SemanticExpression,
    offset: u64,
    pointer_bits: u16,
    expression: SemanticExpression,
    bits: u16,
) -> SemanticEffect {
    SemanticEffect::Store {
        space: SemanticAddressSpace::Default,
        addr: addr_with_offset(base, offset, pointer_bits),
        expression,
        bits,
    }
}

fn load_default(
    base: SemanticExpression,
    offset: u64,
    pointer_bits: u16,
    bits: u16,
) -> SemanticExpression {
    SemanticExpression::Load {
        space: SemanticAddressSpace::Default,
        addr: Box::new(addr_with_offset(base, offset, pointer_bits)),
        bits,
    }
}

fn x87_status_word_image() -> SemanticExpression {
    let top_bits = SemanticExpression::Cast {
        op: SemanticOperationCast::ZeroExtend,
        arg: Box::new(read_reg("x87_top", 3)),
        bits: 16,
    };
    let top_shifted = SemanticExpression::Binary {
        op: SemanticOperationBinary::Shl,
        left: Box::new(top_bits),
        right: Box::new(common::const_u64(11, 16)),
        bits: 16,
    };
    let mut word = common::const_u64(0, 16);
    for (name, bit) in [("x87_c0", 8), ("x87_c1", 9), ("x87_c2", 10), ("x87_c3", 14)] {
        let shifted = SemanticExpression::Binary {
            op: SemanticOperationBinary::Shl,
            left: Box::new(SemanticExpression::Cast {
                op: SemanticOperationCast::ZeroExtend,
                arg: Box::new(read_reg(name, 1)),
                bits: 16,
            }),
            right: Box::new(common::const_u64(bit, 16)),
            bits: 16,
        };
        word = common::or(word, shifted, 16);
    }
    common::or(word, top_shifted, 16)
}

fn mxcsr_location() -> crate::semantics::SemanticLocation {
    common::reg("mxcsr".to_string(), 32)
}

fn string_index_location(
    machine: Architecture,
    destination: bool,
) -> crate::semantics::SemanticLocation {
    let register = match (machine, destination) {
        (Architecture::AMD64, true) => X86Reg::X86_REG_RDI as u16,
        (Architecture::AMD64, false) => X86Reg::X86_REG_RSI as u16,
        (Architecture::I386, true) => X86Reg::X86_REG_EDI as u16,
        (Architecture::I386, false) => X86Reg::X86_REG_ESI as u16,
        (_, true) => X86Reg::X86_REG_RDI as u16,
        (_, false) => X86Reg::X86_REG_RSI as u16,
    };
    common::reg(common::reg_id_name(register), common::pointer_bits(machine))
}

fn next_index_value(
    index: crate::semantics::SemanticLocation,
    bytes: u16,
    machine: Architecture,
) -> SemanticExpression {
    let pointer_bits = common::pointer_bits(machine);
    let current = SemanticExpression::Read(Box::new(index));
    SemanticExpression::Select {
        condition: Box::new(common::flag_expr("df")),
        when_true: Box::new(common::sub(
            current.clone(),
            common::const_u64(bytes as u64, pointer_bits),
            pointer_bits,
        )),
        when_false: Box::new(common::add(
            current,
            common::const_u64(bytes as u64, pointer_bits),
            pointer_bits,
        )),
        bits: pointer_bits,
    }
}

fn stack_pointer_location(machine: Architecture) -> crate::semantics::SemanticLocation {
    let register = match machine {
        Architecture::AMD64 => X86Reg::X86_REG_RSP as u16,
        Architecture::I386 => X86Reg::X86_REG_ESP as u16,
        _ => X86Reg::X86_REG_RSP as u16,
    };
    common::reg(common::reg_id_name(register), common::pointer_bits(machine))
}
