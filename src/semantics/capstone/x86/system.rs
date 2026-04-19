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
    SemanticFenceKind, SemanticOperationCast, SemanticOperationBinary, SemanticTerminator,
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
    _operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    if matches!(instruction.mnemonic().unwrap_or_default(), "pushfd") {
        return pushf(machine, 32);
    }
    if matches!(instruction.mnemonic().unwrap_or_default(), "pause") {
        return Some(common::complete(
            SemanticTerminator::FallThrough,
            vec![SemanticEffect::Nop],
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
    if matches!(instruction.id(), InsnId(id) if id == X86Insn::X86_INS_PUSHFQ as u32) {
        return pushf(machine, 64);
    }
    if matches!(instruction.id(), InsnId(id) if id == X86Insn::X86_INS_POPFQ as u32) {
        return popf(machine, 64);
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
        return random_value(machine, "rdrand", _operands);
    }
    if matches!(instruction.id(), InsnId(id) if id == X86Insn::X86_INS_RDSEED as u32) {
        return random_value(machine, "rdseed", _operands);
    }

    let trap = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_INT3 as u32 => Some(SemanticTrapKind::Breakpoint),
        InsnId(id) if id == X86Insn::X86_INS_INT as u32 => Some(SemanticTrapKind::Interrupt),
        InsnId(id) if id == X86Insn::X86_INS_UD2 as u32 => Some(SemanticTrapKind::InvalidOpcode),
        InsnId(id) if id == X86Insn::X86_INS_SYSCALL as u32 => Some(SemanticTrapKind::Syscall),
        _ => None,
    }?;

    Some(common::complete(
        SemanticTerminator::Trap,
        vec![SemanticEffect::Trap { kind: trap }],
    ))
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
    let value = SemanticExpression::Intrinsic {
        name: "x86.rdtsc".to_string(),
        args: Vec::new(),
        bits: 64,
    };
    common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst: common::reg(common::reg_id_name(X86Reg::X86_REG_EAX as u16), 32),
                expression: SemanticExpression::Extract {
                    arg: Box::new(value.clone()),
                    lsb: 0,
                    bits: 32,
                },
            },
            SemanticEffect::Set {
                dst: common::reg(common::reg_id_name(X86Reg::X86_REG_EDX as u16), 32),
                expression: SemanticExpression::Extract {
                    arg: Box::new(value),
                    lsb: 32,
                    bits: 32,
                },
            },
        ],
    )
}

fn rdtscp() -> InstructionSemantics {
    let value = SemanticExpression::Intrinsic {
        name: "x86.rdtscp".to_string(),
        args: Vec::new(),
        bits: 64,
    };
    let aux = SemanticExpression::Intrinsic {
        name: "x86.rdtscp_aux".to_string(),
        args: Vec::new(),
        bits: 32,
    };
    common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst: common::reg(common::reg_id_name(X86Reg::X86_REG_EAX as u16), 32),
                expression: SemanticExpression::Extract {
                    arg: Box::new(value.clone()),
                    lsb: 0,
                    bits: 32,
                },
            },
            SemanticEffect::Set {
                dst: common::reg(common::reg_id_name(X86Reg::X86_REG_EDX as u16), 32),
                expression: SemanticExpression::Extract {
                    arg: Box::new(value),
                    lsb: 32,
                    bits: 32,
                },
            },
            SemanticEffect::Set {
                dst: common::reg(common::reg_id_name(X86Reg::X86_REG_ECX as u16), 32),
                expression: aux,
            },
        ],
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
    let bits = common::location_bits(&dst);
    let ready = SemanticExpression::Intrinsic {
        name: format!("x86.{name}.ready"),
        args: Vec::new(),
        bits: 1,
    };
    let data = SemanticExpression::Intrinsic {
        name: format!("x86.{name}.data"),
        args: Vec::new(),
        bits,
    };
    let result = SemanticExpression::Select {
        condition: Box::new(ready.clone()),
        when_true: Box::new(data),
        when_false: Box::new(SemanticExpression::Const { value: 0, bits }),
        bits,
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst,
                expression: result,
            },
            SemanticEffect::Set {
                dst: common::flag("cf"),
                expression: ready,
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
