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

use crate::semantics::architectures::x86::helpers as common;
use crate::semantics::architectures::x86::X86InstructionView;
use crate::semantics::architectures::x86::{X86OperandKind, X86OperandView};
use crate::semantics::{
    InstructionSemantics, SemanticEffect, SemanticExpression, SemanticFenceKind,
    SemanticOperationBinary, SemanticTerminator, SemanticTrapKind,
};

pub(crate) fn build(view: &X86InstructionView) -> Option<InstructionSemantics> {
    match view.mnemonic.as_str() {
        "pause"
        | "prefetch"
        | "prefetchnta"
        | "prefetcht0"
        | "prefetcht1"
        | "prefetcht2"
        | "prefetchw"
        | "endbr32"
        | "endbr64"
        | "wait" => Some(nop()),
        "mfence" => Some(fence(SemanticFenceKind::SequentiallyConsistent)),
        "sfence" => Some(fence(SemanticFenceKind::Release)),
        "lfence" => Some(fence(SemanticFenceKind::Acquire)),
        "clflush" => Some(fence(SemanticFenceKind::ArchSpecific {
            name: "x86.clflush".to_string(),
        })),
        "invd" => Some(fence(SemanticFenceKind::ArchSpecific {
            name: "x86.invd".to_string(),
        })),
        "wbinvd" => Some(fence(SemanticFenceKind::ArchSpecific {
            name: "x86.wbinvd".to_string(),
        })),
        "clts" => Some(intrinsic_no_outputs("x86.clts")),
        "invlpg" => invlpg(view),
        "clc" => Some(set_flag("cf", false)),
        "stc" => Some(set_flag("cf", true)),
        "cld" => Some(set_flag("df", false)),
        "std" => Some(set_flag("df", true)),
        "cli" => Some(set_flag("if", false)),
        "sti" => Some(set_flag("if", true)),
        "lahf" => Some(lahf()),
        "sahf" => Some(sahf()),
        "pushf" | "pushfd" => pushf(view.machine, 32),
        "pushfq" => pushf(view.machine, 64),
        "popf" | "popfd" => popf(view.machine, 32),
        "popfq" => popf(view.machine, 64),
        "ldmxcsr" | "vldmxcsr" => ldmxcsr(view),
        "stmxcsr" | "vstmxcsr" => stmxcsr(view),
        "fxsave" => fxsave(view, false),
        "fxsave64" => fxsave(view, true),
        "fxrstor" => fxrstor(view, false),
        "fxrstor64" => fxrstor(view, true),
        "cmc" => Some(common::complete(
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
        )),
        "cpuid" => Some(cpuid()),
        "xgetbv" => Some(xgetbv()),
        "rdtsc" => Some(rdtsc()),
        "rdtscp" => Some(rdtscp()),
        "rdrand" => random_value(view, "rdrand"),
        "rdseed" => random_value(view, "rdseed"),
        "lar" => lar(view),
        "verr" => selector_check(view, "x86.verr"),
        "verw" => selector_check(view, "x86.verw"),
        "insd" => Some(insd(view.machine)),
        "outsd" => Some(outsd(view.machine)),
        "int3" => Some(trap(SemanticTrapKind::Breakpoint)),
        "int" => Some(trap(SemanticTrapKind::Interrupt)),
        "ud2" => Some(trap(SemanticTrapKind::InvalidOpcode)),
        "syscall" => Some(trap(SemanticTrapKind::Syscall)),
        "sysenter" => Some(trap(SemanticTrapKind::ArchSpecific {
            name: "x86.sysenter".to_string(),
        })),
        _ => None,
    }
}

fn nop() -> InstructionSemantics {
    common::complete(SemanticTerminator::FallThrough, vec![SemanticEffect::Nop])
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

fn intrinsic_no_outputs(name: &str) -> InstructionSemantics {
    common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Intrinsic {
            name: name.to_string(),
            args: Vec::new(),
            outputs: Vec::new(),
        }],
    )
}

fn cpuid() -> InstructionSemantics {
    let leaf = SemanticExpression::Read(Box::new(common::reg("eax".to_string(), 32)));
    let subleaf = SemanticExpression::Read(Box::new(common::reg("ecx".to_string(), 32)));
    common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Intrinsic {
            name: "x86.cpuid".to_string(),
            args: vec![leaf, subleaf],
            outputs: vec![
                common::reg("eax".to_string(), 32),
                common::reg("ebx".to_string(), 32),
                common::reg("ecx".to_string(), 32),
                common::reg("edx".to_string(), 32),
            ],
        }],
    )
}

fn xgetbv() -> InstructionSemantics {
    common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Intrinsic {
            name: "x86.xgetbv".to_string(),
            args: Vec::new(),
            outputs: vec![
                common::reg("eax".to_string(), 32),
                common::reg("edx".to_string(), 32),
            ],
        }],
    )
}

fn rdtsc() -> InstructionSemantics {
    common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Intrinsic {
            name: "x86.rdtsc".to_string(),
            args: Vec::new(),
            outputs: vec![
                common::reg("eax".to_string(), 32),
                common::reg("edx".to_string(), 32),
            ],
        }],
    )
}

fn rdtscp() -> InstructionSemantics {
    common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Intrinsic {
            name: "x86.rdtscp".to_string(),
            args: Vec::new(),
            outputs: vec![
                common::reg("eax".to_string(), 32),
                common::reg("edx".to_string(), 32),
                common::reg("ecx".to_string(), 32),
            ],
        }],
    )
}

fn trap(kind: SemanticTrapKind) -> InstructionSemantics {
    common::complete(
        SemanticTerminator::Trap,
        vec![SemanticEffect::Trap { kind }],
    )
}

fn selector_check(view: &X86InstructionView, name: &str) -> Option<InstructionSemantics> {
    let selector = operand_expr(view.machine, view.operands().first()?)?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Intrinsic {
            name: name.to_string(),
            args: vec![selector],
            outputs: vec![common::flag("zf")],
        }],
    ))
}

fn random_value(view: &X86InstructionView, name: &str) -> Option<InstructionSemantics> {
    let dst = operand_location(view.machine, view.operands().first()?)?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Intrinsic {
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

fn lahf() -> InstructionSemantics {
    common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst: common::reg("ah".to_string(), 8),
            expression: flags_low_byte(),
        }],
    )
}

fn ldmxcsr(view: &X86InstructionView) -> Option<InstructionSemantics> {
    let src = operand_expr(view.machine, view.operands().first()?)?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst: mxcsr_location(),
            expression: src,
        }],
    ))
}

fn stmxcsr(view: &X86InstructionView) -> Option<InstructionSemantics> {
    let dst = operand_location(view.machine, view.operands().first()?)?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Read(Box::new(mxcsr_location())),
        }],
    ))
}

fn invlpg(view: &X86InstructionView) -> Option<InstructionSemantics> {
    let addr = operand_expr(view.machine, view.operands().first()?)?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Intrinsic {
            name: "x86.invlpg".to_string(),
            args: vec![addr],
            outputs: Vec::new(),
        }],
    ))
}

fn lar(view: &X86InstructionView) -> Option<InstructionSemantics> {
    let dst = operand_location(view.machine, view.operands().first()?)?;
    let src = operand_expr(view.machine, view.operands().get(1)?)?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Intrinsic {
            name: "x86.lar".to_string(),
            args: vec![src],
            outputs: vec![dst, common::flag("zf")],
        }],
    ))
}

fn fxsave(view: &X86InstructionView, wide_pointers: bool) -> Option<InstructionSemantics> {
    let base = memory_operand_addr(view.machine, view.operands().first()?)?;
    let pointer_bits = common::pointer_bits(view.machine);
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

    let xmm_count = if matches!(view.machine, crate::Architecture::AMD64) {
        16
    } else {
        8
    };
    for index in 0..xmm_count {
        effects.push(store_default(
            base.clone(),
            160 + (index as u64) * 16,
            pointer_bits,
            read_reg(&format!("xmm{index}"), 128),
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

fn fxrstor(view: &X86InstructionView, wide_pointers: bool) -> Option<InstructionSemantics> {
    let base = memory_operand_addr(view.machine, view.operands().first()?)?;
    let pointer_bits = common::pointer_bits(view.machine);
    let fsw = load_default(base.clone(), 2, pointer_bits, 16);
    let mut effects = vec![
        set_reg("x87_fcw", 16, load_default(base.clone(), 0, pointer_bits, 16)),
        set_reg("x87_ftw", 8, load_default(base.clone(), 4, pointer_bits, 8)),
        set_reg("x87_fop", 16, load_default(base.clone(), 6, pointer_bits, 16)),
        set_reg("mxcsr_mask", 32, load_default(base.clone(), 28, pointer_bits, 32)),
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
        effects.push(set_reg(&format!("mm{index}"), 64, mm));
    }

    let xmm_count = if matches!(view.machine, crate::Architecture::AMD64) {
        16
    } else {
        8
    };
    for index in 0..xmm_count {
        effects.push(set_reg(
            &format!("xmm{index}"),
            128,
            load_default(base.clone(), 160 + (index as u64) * 16, pointer_bits, 128),
        ));
    }

    Some(common::complete(SemanticTerminator::FallThrough, effects))
}

fn insd(machine: crate::Architecture) -> InstructionSemantics {
    let di = string_index_location(machine, true);
    let port = io_port_location();
    let addr = SemanticExpression::Read(Box::new(di.clone()));
    let port_addr = SemanticExpression::Read(Box::new(port));
    common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Store {
                space: crate::semantics::SemanticAddressSpace::Default,
                addr,
                expression: SemanticExpression::Load {
                    space: crate::semantics::SemanticAddressSpace::Io,
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
    )
}

fn outsd(machine: crate::Architecture) -> InstructionSemantics {
    let si = string_index_location(machine, false);
    let port = io_port_location();
    let addr = SemanticExpression::Read(Box::new(si.clone()));
    let port_addr = SemanticExpression::Read(Box::new(port));
    common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Store {
                space: crate::semantics::SemanticAddressSpace::Io,
                addr: port_addr,
                expression: SemanticExpression::Load {
                    space: crate::semantics::SemanticAddressSpace::Default,
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
    )
}

fn sahf() -> InstructionSemantics {
    let ah = SemanticExpression::Read(Box::new(common::reg("ah".to_string(), 8)));
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

fn pushf(machine: crate::Architecture, bits: u16) -> Option<InstructionSemantics> {
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
                space: crate::semantics::SemanticAddressSpace::Stack,
                addr: new_sp,
                expression: flags_value,
                bits,
            },
        ],
    ))
}

fn popf(machine: crate::Architecture, bits: u16) -> Option<InstructionSemantics> {
    let stack_pointer = stack_pointer_location(machine);
    let pointer_bits = common::pointer_bits(machine);
    let slot_bytes = (bits / 8) as u64;
    let loaded = SemanticExpression::Load {
        space: crate::semantics::SemanticAddressSpace::Stack,
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
        ("cf", 0u64),
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
                op: crate::semantics::SemanticOperationCast::ZeroExtend,
                arg: Box::new(common::flag_expr(name)),
                bits,
            }),
            right: Box::new(common::const_u64(bit, bits)),
            bits,
        };
        value = common::or(value, shifted, bits);
    }
    value
}

fn flags_low_byte() -> SemanticExpression {
    let mut value = common::const_u64(1 << 1, 8);
    for (name, bit) in [("cf", 0u64), ("pf", 2), ("af", 4), ("zf", 6), ("sf", 7)] {
        let shifted = SemanticExpression::Binary {
            op: SemanticOperationBinary::Shl,
            left: Box::new(SemanticExpression::Cast {
                op: crate::semantics::SemanticOperationCast::ZeroExtend,
                arg: Box::new(common::flag_expr(name)),
                bits: 8,
            }),
            right: Box::new(common::const_u64(bit, 8)),
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

fn stack_pointer_location(machine: crate::Architecture) -> crate::semantics::SemanticLocation {
    let (name, bits) = match machine {
        crate::Architecture::AMD64 => ("rsp", 64),
        crate::Architecture::I386 => ("esp", 32),
        _ => ("rsp", 64),
    };
    common::reg(name.to_string(), bits)
}

fn mxcsr_location() -> crate::semantics::SemanticLocation {
    common::reg("mxcsr".to_string(), 32)
}

fn x87_status_word_image() -> SemanticExpression {
    let top_shifted = SemanticExpression::Binary {
        op: SemanticOperationBinary::Shl,
        left: Box::new(SemanticExpression::Cast {
            op: crate::semantics::SemanticOperationCast::ZeroExtend,
            arg: Box::new(read_reg("x87_top", 3)),
            bits: 16,
        }),
        right: Box::new(common::const_u64(11, 16)),
        bits: 16,
    };
    let mut word = common::const_u64(0, 16);
    for (name, bit) in [("x87_c0", 8), ("x87_c1", 9), ("x87_c2", 10), ("x87_c3", 14)] {
        let shifted = SemanticExpression::Binary {
            op: SemanticOperationBinary::Shl,
            left: Box::new(SemanticExpression::Cast {
                op: crate::semantics::SemanticOperationCast::ZeroExtend,
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

fn io_port_location() -> crate::semantics::SemanticLocation {
    common::reg("dx".to_string(), 16)
}

fn string_index_location(
    machine: crate::Architecture,
    destination: bool,
) -> crate::semantics::SemanticLocation {
    let (name, bits) = match (machine, destination) {
        (crate::Architecture::AMD64, true) => ("rdi", 64),
        (crate::Architecture::AMD64, false) => ("rsi", 64),
        (crate::Architecture::I386, true) => ("edi", 32),
        (crate::Architecture::I386, false) => ("esi", 32),
        (_, true) => ("rdi", 64),
        (_, false) => ("rsi", 64),
    };
    common::reg(name.to_string(), bits)
}

fn next_index_value(
    index: crate::semantics::SemanticLocation,
    bytes: u16,
    machine: crate::Architecture,
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

fn memory_operand_addr(
    machine: crate::Architecture,
    operand: &X86OperandView,
) -> Option<SemanticExpression> {
    let mem = operand.memory_operand()?;
    let base = mem.base_register_name.map(|name| {
        SemanticExpression::Read(Box::new(common::reg(name, common::pointer_bits(machine))))
    });
    let index = mem.index_register_name.map(|name| {
        (
            SemanticExpression::Read(Box::new(common::reg(name, common::pointer_bits(machine)))),
            mem.scale,
        )
    });
    Some(common::memory_addr(machine, base, index, mem.displacement))
}

fn store_default(
    base: SemanticExpression,
    offset: u64,
    pointer_bits: u16,
    expression: SemanticExpression,
    bits: u16,
) -> SemanticEffect {
    SemanticEffect::Store {
        space: crate::semantics::SemanticAddressSpace::Default,
        addr: SemanticExpression::Binary {
            op: SemanticOperationBinary::Add,
            left: Box::new(base),
            right: Box::new(common::const_u64(offset, pointer_bits)),
            bits: pointer_bits,
        },
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
        space: crate::semantics::SemanticAddressSpace::Default,
        addr: Box::new(SemanticExpression::Binary {
            op: SemanticOperationBinary::Add,
            left: Box::new(base),
            right: Box::new(common::const_u64(offset, pointer_bits)),
            bits: pointer_bits,
        }),
        bits,
    }
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

fn operand_expr(machine: crate::Architecture, operand: &X86OperandView) -> Option<SemanticExpression> {
    match operand.kind {
        X86OperandKind::Register => Some(SemanticExpression::Read(Box::new(common::reg(
            operand.register_name()?,
            operand.size_bits,
        )))),
        X86OperandKind::Immediate => Some(SemanticExpression::Const {
            value: operand.immediate_value()? as i128 as u128,
            bits: operand.size_bits,
        }),
        X86OperandKind::Memory => {
            let mem = operand.memory_operand()?;
            let base = mem
                .base_register_name
                .map(|name| SemanticExpression::Read(Box::new(common::reg(name, common::pointer_bits(machine)))));
            let index = mem
                .index_register_name
                .map(|name| (SemanticExpression::Read(Box::new(common::reg(name, common::pointer_bits(machine)))), mem.scale));
            let addr = common::memory_addr(machine, base, index, mem.displacement);
            Some(SemanticExpression::Load {
                space: crate::semantics::SemanticAddressSpace::Default,
                addr: Box::new(addr),
                bits: operand.size_bits,
            })
        }
        _ => None,
    }
}

fn operand_location(
    machine: crate::Architecture,
    operand: &X86OperandView,
) -> Option<crate::semantics::SemanticLocation> {
    match operand.kind {
        X86OperandKind::Register => Some(common::reg(operand.register_name()?, operand.size_bits)),
        X86OperandKind::Memory => {
            let mem = operand.memory_operand()?;
            let base = mem
                .base_register_name
                .map(|name| SemanticExpression::Read(Box::new(common::reg(name, common::pointer_bits(machine)))));
            let index = mem
                .index_register_name
                .map(|name| (SemanticExpression::Read(Box::new(common::reg(name, common::pointer_bits(machine)))), mem.scale));
            let addr = common::memory_addr(machine, base, index, mem.displacement);
            Some(crate::semantics::SemanticLocation::Memory {
                space: crate::semantics::SemanticAddressSpace::Default,
                addr: Box::new(addr),
                bits: operand.size_bits,
            })
        }
        _ => None,
    }
}
