use std::collections::BTreeMap;

use crate::controlflow::{Graph, Instruction};
use crate::disassemblers::capstone::Disassembler;
use crate::semantics::{
    InstructionSemantics, SemanticEffect, SemanticExpression, SemanticLocation,
    SemanticOperationBinary, SemanticOperationCast, SemanticOperationCompare,
    SemanticOperationUnary, SemanticStatus, SemanticTerminator,
};
use crate::{Architecture, Config};
use num_bigint::BigUint;
use num_traits::{One, ToPrimitive, Zero};

use super::memory::{fixture_memory_map, load_le_bytes, load_le_value, value_to_le_bytes};
use super::registers::{
    normalize_register_name, read_register_value, read_register_value_wide, register_by_name,
    stable_register_name, write_register_value, write_register_value_wide,
};
use super::unicorn::{decode_eflags, unicorn_amd64_single_instruction_wide, unicorn_x86_execution};

pub(crate) const I386_CODE_ADDRESS: u64 = 0x1000;
pub(crate) const I386_CODE_PAGE_SIZE: u64 = 0x1000;
pub(crate) const I386_STACK_ADDRESS: u64 = 0x2000;
pub(crate) const I386_STACK_PAGE_SIZE: u64 = 0x1000;
pub(crate) const I386_DATA_ADDRESS: u64 = 0x3000;
pub(crate) const I386_DATA_PAGE_SIZE: u64 = 0x2000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct X86Flags {
    pub cf: bool,
    pub pf: bool,
    pub af: bool,
    pub zf: bool,
    pub sf: bool,
    pub if_flag: bool,
    pub of: bool,
    pub df: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum I386Register {
    Eax,
    Rax,
    Ebx,
    Rbx,
    Ecx,
    Rcx,
    Edx,
    Rdx,
    Esi,
    Rsi,
    Edi,
    Rdi,
    Ebp,
    Rbp,
    Esp,
    Rsp,
    Xmm0,
    Xmm1,
    Xmm2,
    Ymm0,
    Ymm1,
    Ymm2,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct I386CpuState {
    pub registers: BTreeMap<String, u128>,
    pub eip: u32,
    pub eflags: u32,
    pub flags: X86Flags,
    pub memory: BTreeMap<u64, u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct I386Transition {
    pub pre: I386CpuState,
    pub post: I386CpuState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct I386Execution {
    pub(crate) transition: I386Transition,
    pub(crate) memory_writes: Vec<(u64, usize)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct I386CpuStateWide {
    pub(crate) registers: BTreeMap<String, BigUint>,
    pub(crate) eip: u32,
    pub(crate) eflags: u32,
    pub(crate) flags: X86Flags,
    pub(crate) memory: BTreeMap<u64, u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct I386TransitionWide {
    pub(crate) pre: I386CpuStateWide,
    pub(crate) post: I386CpuStateWide,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct I386ExecutionWide {
    pub(crate) transition: I386TransitionWide,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct I386Fixture {
    pub registers: Vec<(I386Register, u128)>,
    pub eflags: u32,
    pub memory: Vec<(u64, Vec<u8>)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WideI386Fixture {
    pub base: I386Fixture,
    pub wide_registers: Vec<(I386Register, Vec<u8>)>,
}

pub(crate) fn disassemble_x86_single(
    name: &str,
    architecture: Architecture,
    bytes: &[u8],
) -> Instruction {
    let config = Config::default();
    let mut ranges = BTreeMap::new();
    ranges.insert(0, bytes.len() as u64);

    let mut graph = Graph::new(architecture, config.clone());
    let disassembler =
        Disassembler::from_bytes(architecture, bytes, ranges, config).expect("disassembler");
    disassembler
        .disassemble_instruction(0, &mut graph)
        .unwrap_or_else(|error| panic!("{name}: instruction should disassemble: {error}"));
    graph.get_instruction(0).expect("instruction should exist")
}

pub(crate) fn semantics(
    name: &str,
    architecture: Architecture,
    bytes: &[u8],
) -> InstructionSemantics {
    disassemble_x86_single(name, architecture, bytes)
        .semantics
        .expect("instruction should have semantics")
}

pub(crate) fn assert_complete_semantics(name: &str, architecture: Architecture, bytes: &[u8]) {
    let semantics = semantics(name, architecture, bytes);
    assert_eq!(
        semantics.status,
        SemanticStatus::Complete,
        "{name}: expected complete semantics, got {:?} with diagnostics {:?}",
        semantics.status,
        semantics
            .diagnostics
            .iter()
            .map(|diagnostic| diagnostic.message.clone())
            .collect::<Vec<_>>()
    );
    assert!(
        semantics.diagnostics.is_empty(),
        "{name}: expected no diagnostics, got {:?}",
        semantics
            .diagnostics
            .iter()
            .map(|diagnostic| diagnostic.message.clone())
            .collect::<Vec<_>>()
    );
}

pub(crate) fn assert_i386_semantics_match_unicorn(name: &str, bytes: &[u8], fixture: I386Fixture) {
    assert_x86_semantics_match_unicorn(name, Architecture::I386, bytes, fixture);
}

pub(crate) fn assert_amd64_semantics_match_unicorn(name: &str, bytes: &[u8], fixture: I386Fixture) {
    assert_x86_semantics_match_unicorn(name, Architecture::AMD64, bytes, fixture);
}

pub(crate) fn assert_i386_instruction_roundtrip_match_unicorn(
    name: &str,
    bytes: &[u8],
    fixture: I386Fixture,
) {
    assert_x86_instruction_roundtrip_match_unicorn(name, Architecture::I386, bytes, fixture);
}

pub(crate) fn assert_amd64_instruction_roundtrip_match_unicorn(
    name: &str,
    bytes: &[u8],
    fixture: I386Fixture,
) {
    assert_x86_instruction_roundtrip_match_unicorn(name, Architecture::AMD64, bytes, fixture);
}

fn assert_x86_instruction_roundtrip_match_unicorn(
    name: &str,
    architecture: Architecture,
    bytes: &[u8],
    fixture: I386Fixture,
) {
    assert_x86_semantics_match_unicorn(name, architecture, bytes, fixture);
}

#[allow(dead_code)]
pub(crate) fn assert_amd64_wide_semantics_match_unicorn(
    name: &str,
    bytes: &[u8],
    fixture: WideI386Fixture,
) {
    assert_amd64_semantics_match_unicorn_wide_impl(name, bytes, fixture);
}

pub(crate) fn interpret_amd64_wide_semantics(
    name: &str,
    bytes: &[u8],
    fixture: WideI386Fixture,
) -> (BTreeMap<String, Vec<u8>>, X86Flags) {
    let semantics = semantics(name, Architecture::AMD64, bytes);
    let (written_registers, _) = written_state(&semantics);
    let tracked_registers = tracked_registers_for_wide_fixture(&fixture, &written_registers);
    let interpreted =
        interpret_amd64_semantics_wide(bytes, &semantics, &fixture, &tracked_registers);
    let registers = interpreted
        .transition
        .post
        .registers
        .into_iter()
        .map(|(name, value)| {
            let register = register_by_name(&name).expect("known tracked register");
            let byte_len = (register.bit_width() / 8) as usize;
            (name, biguint_to_padded_le_bytes(&value, byte_len))
        })
        .collect();
    (registers, interpreted.transition.post.flags)
}

pub(crate) fn interpret_amd64_semantics(
    name: &str,
    bytes: &[u8],
    fixture: I386Fixture,
) -> I386Transition {
    let semantics = semantics(name, Architecture::AMD64, bytes);
    interpret_i386_semantics(Architecture::AMD64, bytes, &semantics, fixture).transition
}

fn assert_x86_semantics_match_unicorn(
    name: &str,
    architecture: Architecture,
    bytes: &[u8],
    fixture: I386Fixture,
) {
    let semantics = semantics(name, architecture, bytes);
    let interpreted = interpret_i386_semantics(architecture, bytes, &semantics, fixture.clone());
    let instruction_count = if semantics
        .effects
        .iter()
        .any(|effect| {
            matches!(
                effect,
                SemanticEffect::MemorySet { .. } | SemanticEffect::MemoryCopy { .. }
            )
        }) {
        0
    } else {
        1
    };
    let unicorn = unicorn_x86_execution(
        architecture,
        bytes,
        fixture,
        &interpreted.memory_writes,
        I386_CODE_ADDRESS,
        I386_CODE_ADDRESS + bytes.len() as u64,
        instruction_count,
    );

    assert_eq!(
        unicorn.transition.pre, interpreted.transition.pre,
        "{name}: semantics pre-state diverged from unicorn pre-state"
    );
    assert_eq!(
        unicorn.transition.post.eip, interpreted.transition.post.eip,
        "{name}: eip mismatch\nunicorn: {:#010x}\nsemantics: {:#010x}",
        unicorn.transition.post.eip, interpreted.transition.post.eip
    );

    let (written_registers, written_flags) = written_state(&semantics);
    for register in written_registers {
        let unicorn_value = unicorn
            .transition
            .post
            .registers
            .get(&register)
            .copied()
            .unwrap_or_default();
        let interpreted_value = interpreted
            .transition
            .post
            .registers
            .get(&register)
            .copied()
            .unwrap_or_default();
        assert_eq!(
            unicorn_value, interpreted_value,
            "{name}: register {register} mismatch\nunicorn: {:#x}\nsemantics: {:#x}",
            unicorn_value, interpreted_value
        );
    }
    for flag in written_flags {
        let unicorn_value = flag_value(&unicorn.transition.post.flags, &flag);
        let interpreted_value = flag_value(&interpreted.transition.post.flags, &flag);
        assert_eq!(
            unicorn_value, interpreted_value,
            "{name}: flag {flag} mismatch\nunicorn: {}\nsemantics: {}",
            unicorn_value, interpreted_value
        );
    }
    for (address, size) in &interpreted.memory_writes {
        for offset in 0..*size {
            let byte_address = address + offset as u64;
            let unicorn_value = unicorn
                .transition
                .post
                .memory
                .get(&byte_address)
                .copied()
                .unwrap_or_default();
            let interpreted_value = interpreted
                .transition
                .post
                .memory
                .get(&byte_address)
                .copied()
                .unwrap_or_default();
            assert_eq!(
                unicorn_value, interpreted_value,
                "{name}: memory byte mismatch at 0x{byte_address:x}\nunicorn: {:#04x}\nsemantics: {:#04x}",
                unicorn_value, interpreted_value
            );
        }
    }
}

#[allow(dead_code)]
fn assert_amd64_semantics_match_unicorn_wide_impl(
    name: &str,
    bytes: &[u8],
    fixture: WideI386Fixture,
) {
    let semantics = semantics(name, Architecture::AMD64, bytes);
    let (written_registers, written_flags) = written_state(&semantics);
    let tracked_registers = tracked_registers_for_wide_fixture(&fixture, &written_registers);
    let interpreted =
        interpret_amd64_semantics_wide(bytes, &semantics, &fixture, &tracked_registers);
    let unicorn = unicorn_amd64_single_instruction_wide(bytes, &fixture, &tracked_registers);

    assert_eq!(
        unicorn.transition.pre, interpreted.transition.pre,
        "{name}: semantics pre-state diverged from unicorn pre-state"
    );
    assert_eq!(
        unicorn.transition.post.eip, interpreted.transition.post.eip,
        "{name}: eip mismatch\nunicorn: {:#010x}\nsemantics: {:#010x}",
        unicorn.transition.post.eip, interpreted.transition.post.eip
    );

    for register in written_registers {
        let unicorn_value = unicorn
            .transition
            .post
            .registers
            .get(&register)
            .cloned()
            .unwrap_or_else(BigUint::zero);
        let interpreted_value = interpreted
            .transition
            .post
            .registers
            .get(&register)
            .cloned()
            .unwrap_or_else(BigUint::zero);
        assert_eq!(
            unicorn_value,
            interpreted_value,
            "{name}: register {register} mismatch\nunicorn: 0x{}\nsemantics: 0x{}",
            unicorn_value.to_str_radix(16),
            interpreted_value.to_str_radix(16)
        );
    }
    for flag in written_flags {
        let unicorn_value = flag_value(&unicorn.transition.post.flags, &flag);
        let interpreted_value = flag_value(&interpreted.transition.post.flags, &flag);
        assert_eq!(
            unicorn_value, interpreted_value,
            "{name}: flag {flag} mismatch\nunicorn: {}\nsemantics: {}",
            unicorn_value, interpreted_value
        );
    }
}

fn tracked_registers_for_wide_fixture(
    fixture: &WideI386Fixture,
    written_registers: &[String],
) -> Vec<I386Register> {
    let mut tracked = fixture
        .base
        .registers
        .iter()
        .map(|(register, _)| *register)
        .collect::<Vec<_>>();
    for (register, _) in &fixture.wide_registers {
        if !tracked.contains(register) {
            tracked.push(*register);
        }
    }
    for name in written_registers {
        if let Some(register) = register_by_name(name) {
            if !tracked.contains(&register) {
                tracked.push(register);
            }
        }
    }
    tracked
}

fn interpret_i386_semantics(
    architecture: Architecture,
    bytes: &[u8],
    semantics: &InstructionSemantics,
    fixture: I386Fixture,
) -> I386Execution {
    let mut registers = I386Register::all_for_arch(architecture)
        .into_iter()
        .map(|register| (stable_register_name(register).to_string(), 0u128))
        .collect::<BTreeMap<_, _>>();
    for (register, value) in &fixture.registers {
        write_register_value(&mut registers, stable_register_name(*register), *value as u128);
    }
    let mut flags = BTreeMap::<String, u128>::new();
    let decoded = decode_eflags(fixture.eflags);
    flags.insert("cf".to_string(), decoded.cf as u128);
    flags.insert("pf".to_string(), decoded.pf as u128);
    flags.insert("af".to_string(), decoded.af as u128);
    flags.insert("zf".to_string(), decoded.zf as u128);
    flags.insert("sf".to_string(), decoded.sf as u128);
    flags.insert("if".to_string(), decoded.if_flag as u128);
    flags.insert("of".to_string(), decoded.of as u128);
    flags.insert("df".to_string(), decoded.df as u128);

    let pre = I386CpuState {
        registers: registers.clone(),
        eip: I386_CODE_ADDRESS as u32,
        eflags: fixture.eflags,
        flags: decoded,
        memory: fixture_memory_map(&fixture.memory),
    };

    let mut register_writes = Vec::<(String, u128)>::new();
    let mut flag_writes = Vec::<(String, u128)>::new();
    let mut memory_writes = Vec::<(u64, Vec<u8>)>::new();
    let mut temporaries = BTreeMap::<u32, u128>::new();
    for effect in &semantics.effects {
        match effect {
            SemanticEffect::Set { dst, expression } => match dst {
                SemanticLocation::Temporary { id, bits } => {
                    if is_directly_undefined(expression) {
                        continue;
                    }
                    let value =
                        eval_expression(expression, &registers, &flags, &pre.memory, &temporaries);
                    temporaries.insert(*id, mask_to_bits(value, *bits));
                }
                SemanticLocation::Register { name, bits } => {
                    if is_directly_undefined(expression) {
                        continue;
                    }
                    let value =
                        eval_expression(expression, &registers, &flags, &pre.memory, &temporaries);
                    register_writes.push((name.clone(), mask_to_bits(value, *bits)));
                }
                SemanticLocation::Flag { name, .. } => {
                    if is_directly_undefined(expression) {
                        continue;
                    }
                    let value =
                        eval_expression(expression, &registers, &flags, &pre.memory, &temporaries);
                    flag_writes.push((name.clone(), value & 1));
                }
                SemanticLocation::Memory { addr, bits, .. } => {
                    if is_directly_undefined(expression) {
                        continue;
                    }
                    let address =
                        eval_expression(addr, &registers, &flags, &pre.memory, &temporaries) as u64;
                    let value =
                        eval_expression(expression, &registers, &flags, &pre.memory, &temporaries);
                    memory_writes.push((address, value_to_le_bytes(value, *bits)));
                }
                other => panic!("unsupported i386 test destination: {other:?}"),
            },
            SemanticEffect::Store {
                addr,
                expression,
                bits,
                ..
            } => {
                let address =
                    eval_expression(addr, &registers, &flags, &pre.memory, &temporaries) as u64;
                let value =
                    eval_expression(expression, &registers, &flags, &pre.memory, &temporaries);
                memory_writes.push((address, value_to_le_bytes(value, *bits)));
            }
            SemanticEffect::MemorySet {
                addr,
                value,
                count,
                element_bits,
                decrement,
                ..
            } => {
                let base =
                    eval_expression(addr, &registers, &flags, &pre.memory, &temporaries) as u64;
                let fill_value =
                    eval_expression(value, &registers, &flags, &pre.memory, &temporaries);
                let count =
                    eval_expression(count, &registers, &flags, &pre.memory, &temporaries) as usize;
                let decrement =
                    eval_expression(decrement, &registers, &flags, &pre.memory, &temporaries) != 0;
                let step = (*element_bits / 8) as usize;
                let element_bytes = value_to_le_bytes(fill_value, *element_bits);
                for index in 0..count {
                    let address = if decrement {
                        base.wrapping_sub((index * step) as u64)
                    } else {
                        base + (index * step) as u64
                    };
                    memory_writes.push((address, element_bytes.clone()));
                }
            }
            SemanticEffect::MemoryCopy {
                src_addr,
                dst_addr,
                count,
                element_bits,
                decrement,
                ..
            } => {
                let src_base =
                    eval_expression(src_addr, &registers, &flags, &pre.memory, &temporaries) as u64;
                let dst_base =
                    eval_expression(dst_addr, &registers, &flags, &pre.memory, &temporaries) as u64;
                let count =
                    eval_expression(count, &registers, &flags, &pre.memory, &temporaries) as usize;
                let decrement =
                    eval_expression(decrement, &registers, &flags, &pre.memory, &temporaries) != 0;
                let step = (*element_bits / 8) as usize;
                for index in 0..count {
                    let src = if decrement {
                        src_base.wrapping_sub((index * step) as u64)
                    } else {
                        src_base + (index * step) as u64
                    };
                    let dst = if decrement {
                        dst_base.wrapping_sub((index * step) as u64)
                    } else {
                        dst_base + (index * step) as u64
                    };
                    memory_writes.push((dst, load_le_bytes(&pre.memory, src, *element_bits)));
                }
            }
            SemanticEffect::Fence { .. } | SemanticEffect::Nop => {}
            other => panic!("unsupported i386 test effect: {other:?}"),
        }
    }
    for (name, value) in register_writes {
        write_register_value(&mut registers, &name, value);
    }
    for (name, value) in flag_writes {
        flags.insert(name, value);
    }
    let mut post_memory = pre.memory.clone();
    let mut written_ranges = Vec::<(u64, usize)>::new();
    for (address, bytes) in memory_writes {
        if !written_ranges.contains(&(address, bytes.len())) {
            written_ranges.push((address, bytes.len()));
        }
        for (offset, byte) in bytes.into_iter().enumerate() {
            post_memory.insert(address + offset as u64, byte);
        }
    }

    let post_flags = X86Flags {
        cf: read_flag(&flags, "cf"),
        pf: read_flag(&flags, "pf"),
        af: read_flag(&flags, "af"),
        zf: read_flag(&flags, "zf"),
        sf: read_flag(&flags, "sf"),
        if_flag: read_flag(&flags, "if"),
        of: read_flag(&flags, "of"),
        df: read_flag(&flags, "df"),
    };
    let stack_register = match architecture {
        Architecture::AMD64 => stable_register_name(I386Register::Rsp),
        _ => stable_register_name(I386Register::Esp),
    };
    let post_eip = match &semantics.terminator {
        SemanticTerminator::FallThrough => I386_CODE_ADDRESS as u32 + bytes.len() as u32,
        SemanticTerminator::Return { expression } => {
            let stack_pointer = read_register_value(&registers, stack_register, 32) as u64;
            let return_target = u32::from_le_bytes(
                load_le_bytes(&post_memory, stack_pointer, 32)
                    .try_into()
                    .expect("return target should be 4 bytes"),
            );
            let extra = expression
                .as_ref()
                .map(|expr| eval_expression(expr, &registers, &flags, &post_memory, &temporaries))
                .unwrap_or_default();
            write_register_value(
                &mut registers,
                stack_register,
                stack_pointer as u128 + 4 + extra,
            );
            return_target
        }
        other => panic!("unsupported i386 test terminator: {other:?}"),
    };
    let post = I386CpuState {
        registers,
        eip: post_eip,
        eflags: encode_modeled_eflags(post_flags),
        flags: post_flags,
        memory: post_memory,
    };

    I386Execution {
        transition: I386Transition { pre, post },
        memory_writes: written_ranges,
    }
}

fn interpret_amd64_semantics_wide(
    bytes: &[u8],
    semantics: &InstructionSemantics,
    fixture: &WideI386Fixture,
    tracked_registers: &[I386Register],
) -> I386ExecutionWide {
    assert_eq!(
        semantics.terminator,
        SemanticTerminator::FallThrough,
        "wide conformance helper only supports fallthrough instructions"
    );

    let mut registers = tracked_registers
        .iter()
        .map(|register| {
            (stable_register_name(*register).to_string(), BigUint::zero())
        })
        .collect::<BTreeMap<_, _>>();
    for (register, value) in &fixture.base.registers {
        write_register_value_wide(
            &mut registers,
            stable_register_name(*register),
            BigUint::from(*value),
        );
    }
    for (register, bytes) in &fixture.wide_registers {
        write_register_value_wide(
            &mut registers,
            stable_register_name(*register),
            BigUint::from_bytes_le(bytes),
        );
    }

    let mut flags = BTreeMap::<String, BigUint>::new();
    let decoded = decode_eflags(fixture.base.eflags);
    flags.insert("cf".to_string(), BigUint::from(decoded.cf as u8));
    flags.insert("pf".to_string(), BigUint::from(decoded.pf as u8));
    flags.insert("af".to_string(), BigUint::from(decoded.af as u8));
    flags.insert("zf".to_string(), BigUint::from(decoded.zf as u8));
    flags.insert("sf".to_string(), BigUint::from(decoded.sf as u8));
    flags.insert("if".to_string(), BigUint::from(decoded.if_flag as u8));
    flags.insert("of".to_string(), BigUint::from(decoded.of as u8));
    flags.insert("df".to_string(), BigUint::from(decoded.df as u8));

    let pre = I386CpuStateWide {
        registers: registers.clone(),
        eip: I386_CODE_ADDRESS as u32,
        eflags: fixture.base.eflags,
        flags: decoded,
        memory: fixture_memory_map(&fixture.base.memory),
    };

    let mut register_writes = Vec::<(String, BigUint)>::new();
    let mut flag_writes = Vec::<(String, BigUint)>::new();
    let mut temporaries = BTreeMap::<u32, BigUint>::new();
    for effect in &semantics.effects {
        match effect {
            SemanticEffect::Set { dst, expression } => match dst {
                SemanticLocation::Temporary { id, bits } => {
                    if is_directly_undefined(expression) {
                        continue;
                    }
                    let value = eval_expression_wide(
                        expression,
                        &registers,
                        &flags,
                        &pre.memory,
                        &temporaries,
                    );
                    temporaries.insert(*id, mask_to_bits_wide(value, *bits));
                }
                SemanticLocation::Register { name, bits } => {
                    if is_directly_undefined(expression) {
                        continue;
                    }
                    let value = eval_expression_wide(
                        expression,
                        &registers,
                        &flags,
                        &pre.memory,
                        &temporaries,
                    );
                    register_writes.push((name.clone(), mask_to_bits_wide(value, *bits)));
                }
                SemanticLocation::Flag { name, .. } => {
                    if is_directly_undefined(expression) {
                        continue;
                    }
                    let value = eval_expression_wide(
                        expression,
                        &registers,
                        &flags,
                        &pre.memory,
                        &temporaries,
                    );
                    flag_writes.push((name.clone(), value & BigUint::from(1u8)));
                }
                other => panic!("unsupported wide test destination: {other:?}"),
            },
            SemanticEffect::Fence { .. } | SemanticEffect::Nop => {}
            other => panic!("unsupported wide test effect: {other:?}"),
        }
    }

    for (name, value) in register_writes {
        write_register_value_wide(&mut registers, &name, value);
    }
    for (name, value) in flag_writes {
        flags.insert(name, value);
    }

    let post_flags = X86Flags {
        cf: read_flag_wide(&flags, "cf"),
        pf: read_flag_wide(&flags, "pf"),
        af: read_flag_wide(&flags, "af"),
        zf: read_flag_wide(&flags, "zf"),
        sf: read_flag_wide(&flags, "sf"),
        if_flag: read_flag_wide(&flags, "if"),
        of: read_flag_wide(&flags, "of"),
        df: read_flag_wide(&flags, "df"),
    };
    let post = I386CpuStateWide {
        registers,
        eip: I386_CODE_ADDRESS as u32 + bytes.len() as u32,
        eflags: encode_modeled_eflags(post_flags),
        flags: post_flags,
        memory: pre.memory.clone(),
    };

    I386ExecutionWide {
        transition: I386TransitionWide { pre, post },
    }
}

fn eval_expression_wide(
    expression: &SemanticExpression,
    registers: &BTreeMap<String, BigUint>,
    flags: &BTreeMap<String, BigUint>,
    memory: &BTreeMap<u64, u8>,
    temporaries: &BTreeMap<u32, BigUint>,
) -> BigUint {
    match expression {
        SemanticExpression::Const { value, bits } => {
            mask_to_bits_wide(BigUint::from(*value), *bits)
        }
        SemanticExpression::Read(location) => match location.as_ref() {
            SemanticLocation::Register { name, bits } => {
                mask_to_bits_wide(read_register_value_wide(registers, name, *bits), *bits)
            }
            SemanticLocation::Flag { name, .. } => {
                flags.get(name).cloned().unwrap_or_else(BigUint::zero)
            }
            SemanticLocation::Temporary { id, bits } => mask_to_bits_wide(
                temporaries.get(id).cloned().unwrap_or_else(BigUint::zero),
                *bits,
            ),
            other => panic!("unsupported wide read location: {other:?}"),
        },
        SemanticExpression::Load { addr, bits, .. } => {
            let address = eval_expression_wide(addr, registers, flags, memory, temporaries)
                .to_u64()
                .expect("wide address should fit in u64");
            load_le_value_wide(memory, address, *bits)
        }
        SemanticExpression::Unary { op, arg, bits } => {
            let value = eval_expression_wide(arg, registers, flags, memory, temporaries);
            match op {
                SemanticOperationUnary::Not => {
                    mask_to_bits_wide(mask_for_bits_wide(*bits) ^ value, *bits)
                }
                SemanticOperationUnary::Neg => {
                    let modulus = BigUint::one() << (*bits as usize);
                    mask_to_bits_wide(modulus - mask_to_bits_wide(value, *bits), *bits)
                }
                SemanticOperationUnary::CountLeadingZeros => BigUint::from(
                    count_leading_zeros_wide(mask_to_bits_wide(value, *bits), *bits) as u64,
                ),
                SemanticOperationUnary::CountTrailingZeros => BigUint::from(
                    count_trailing_zeros_wide(mask_to_bits_wide(value, *bits), *bits) as u64,
                ),
                SemanticOperationUnary::PopCount => BigUint::from(
                    value
                        .to_bytes_le()
                        .iter()
                        .map(|byte| byte.count_ones() as u64)
                        .sum::<u64>(),
                ),
                other => panic!("unsupported wide unary op: {other:?}"),
            }
        }
        SemanticExpression::Binary {
            op,
            left,
            right,
            bits,
        } => {
            let left = eval_expression_wide(left, registers, flags, memory, temporaries);
            let right = eval_expression_wide(right, registers, flags, memory, temporaries);
            let value = match op {
                SemanticOperationBinary::Add => left + right,
                SemanticOperationBinary::Sub => {
                    let modulus = BigUint::one() << (*bits as usize);
                    if left >= right {
                        left - right
                    } else {
                        modulus - (right - left)
                    }
                }
                SemanticOperationBinary::Mul => left * right,
                SemanticOperationBinary::And => left & right,
                SemanticOperationBinary::Or => left | right,
                SemanticOperationBinary::Xor => left ^ right,
                SemanticOperationBinary::Shl => left << shift_amount(&right),
                SemanticOperationBinary::LShr => left >> shift_amount(&right),
                SemanticOperationBinary::AShr => arithmetic_shift_right_wide(left, right, *bits),
                SemanticOperationBinary::MinUnsigned => left.min(right),
                SemanticOperationBinary::MinSigned => {
                    match compare_signed_wide(&left, &right, *bits) {
                        std::cmp::Ordering::Greater => right,
                        _ => left,
                    }
                }
                SemanticOperationBinary::MaxUnsigned => left.max(right),
                SemanticOperationBinary::MaxSigned => {
                    match compare_signed_wide(&left, &right, *bits) {
                        std::cmp::Ordering::Less => right,
                        _ => left,
                    }
                }
                other => panic!("unsupported wide binary op: {other:?}"),
            };
            mask_to_bits_wide(value, *bits)
        }
        SemanticExpression::Cast { op, arg, bits } => {
            let value = eval_expression_wide(arg, registers, flags, memory, temporaries);
            match op {
                SemanticOperationCast::ZeroExtend
                | SemanticOperationCast::Bitcast
                | SemanticOperationCast::Truncate => mask_to_bits_wide(value, *bits),
                SemanticOperationCast::SignExtend => {
                    mask_to_bits_wide(sign_extend_wide(value, arg_bits(arg), *bits), *bits)
                }
                other => panic!("unsupported wide cast op: {other:?}"),
            }
        }
        SemanticExpression::Compare {
            op, left, right, ..
        } => {
            let compare_bits = arg_bits(left);
            let left = eval_expression_wide(left, registers, flags, memory, temporaries);
            let right = eval_expression_wide(right, registers, flags, memory, temporaries);
            let value = match op {
                SemanticOperationCompare::Eq => left == right,
                SemanticOperationCompare::Ne => left != right,
                SemanticOperationCompare::Ult => left < right,
                SemanticOperationCompare::Ule => left <= right,
                SemanticOperationCompare::Ugt => left > right,
                SemanticOperationCompare::Uge => left >= right,
                SemanticOperationCompare::Slt => {
                    compare_signed_wide(&left, &right, compare_bits) == std::cmp::Ordering::Less
                }
                SemanticOperationCompare::Sle => {
                    compare_signed_wide(&left, &right, compare_bits) != std::cmp::Ordering::Greater
                }
                SemanticOperationCompare::Sgt => {
                    compare_signed_wide(&left, &right, compare_bits) == std::cmp::Ordering::Greater
                }
                SemanticOperationCompare::Sge => {
                    compare_signed_wide(&left, &right, compare_bits) != std::cmp::Ordering::Less
                }
                other => panic!("unsupported wide compare op: {other:?}"),
            };
            BigUint::from(value as u8)
        }
        SemanticExpression::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            if !eval_expression_wide(condition, registers, flags, memory, temporaries).is_zero() {
                eval_expression_wide(when_true, registers, flags, memory, temporaries)
            } else {
                eval_expression_wide(when_false, registers, flags, memory, temporaries)
            }
        }
        SemanticExpression::Extract { arg, lsb, bits } => mask_to_bits_wide(
            eval_expression_wide(arg, registers, flags, memory, temporaries) >> (*lsb as usize),
            *bits,
        ),
        SemanticExpression::Concat { parts, bits } => {
            let mut value = BigUint::zero();
            let mut shift = 0usize;
            for part in parts.iter().rev() {
                let part_bits = arg_bits(part) as usize;
                value |= eval_expression_wide(part, registers, flags, memory, temporaries) << shift;
                shift += part_bits;
            }
            mask_to_bits_wide(value, *bits)
        }
        other => panic!("unsupported wide expression: {other:?}"),
    }
}

fn eval_expression(
    expression: &SemanticExpression,
    registers: &BTreeMap<String, u128>,
    flags: &BTreeMap<String, u128>,
    memory: &BTreeMap<u64, u8>,
    temporaries: &BTreeMap<u32, u128>,
) -> u128 {
    match expression {
        SemanticExpression::Const { value, bits } => mask_to_bits(*value, *bits),
        SemanticExpression::Read(location) => match location.as_ref() {
            SemanticLocation::Register { name, bits } => {
                mask_to_bits(read_register_value(registers, name, *bits), *bits)
            }
            SemanticLocation::Flag { name, .. } => *flags.get(name).expect("known flag read") & 1,
            SemanticLocation::Temporary { id, bits } => {
                mask_to_bits(*temporaries.get(id).expect("known temporary read"), *bits)
            }
            other => panic!("unsupported i386 test read location: {other:?}"),
        },
        SemanticExpression::Load { addr, bits, .. } => {
            let address = eval_expression(addr, registers, flags, memory, temporaries) as u64;
            load_le_value(memory, address, *bits)
        }
        SemanticExpression::Unary { op, arg, bits } => {
            let value = eval_expression(arg, registers, flags, memory, temporaries);
            match op {
                SemanticOperationUnary::Not => mask_to_bits(!value, *bits),
                SemanticOperationUnary::Neg => mask_to_bits((0u128).wrapping_sub(value), *bits),
                SemanticOperationUnary::ByteSwap => mask_to_bits(byte_swap(value, *bits), *bits),
                SemanticOperationUnary::CountLeadingZeros => mask_to_bits(
                    count_leading_zeros(mask_to_bits(value, *bits), *bits) as u128,
                    *bits,
                ),
                SemanticOperationUnary::CountTrailingZeros => mask_to_bits(
                    count_trailing_zeros(mask_to_bits(value, *bits), *bits) as u128,
                    *bits,
                ),
                SemanticOperationUnary::PopCount => {
                    mask_to_bits((value.count_ones() as u128) & mask_for_bits(*bits), *bits)
                }
                other => panic!("unsupported i386 test unary op: {other:?}"),
            }
        }
        SemanticExpression::Binary {
            op,
            left,
            right,
            bits,
        } => {
            let left = eval_expression(left, registers, flags, memory, temporaries);
            let right = eval_expression(right, registers, flags, memory, temporaries);
            let value = match op {
                SemanticOperationBinary::Add => left.wrapping_add(right),
                SemanticOperationBinary::Sub => left.wrapping_sub(right),
                SemanticOperationBinary::Mul => left.wrapping_mul(right),
                SemanticOperationBinary::UDiv => {
                    let lhs = mask_to_bits(left, *bits);
                    let rhs = mask_to_bits(right, *bits);
                    lhs / rhs
                }
                SemanticOperationBinary::SDiv => {
                    let lhs = sign_extend(left, *bits, 128) as i128;
                    let rhs = sign_extend(right, *bits, 128) as i128;
                    (lhs / rhs) as u128
                }
                SemanticOperationBinary::URem => {
                    let lhs = mask_to_bits(left, *bits);
                    let rhs = mask_to_bits(right, *bits);
                    lhs % rhs
                }
                SemanticOperationBinary::SRem => {
                    let lhs = sign_extend(left, *bits, 128) as i128;
                    let rhs = sign_extend(right, *bits, 128) as i128;
                    (lhs % rhs) as u128
                }
                SemanticOperationBinary::FAdd => u128::from(
                    (f64::from_bits(left as u64) + f64::from_bits(right as u64)).to_bits(),
                ),
                SemanticOperationBinary::FSub => u128::from(
                    (f64::from_bits(left as u64) - f64::from_bits(right as u64)).to_bits(),
                ),
                SemanticOperationBinary::FMul => u128::from(
                    (f64::from_bits(left as u64) * f64::from_bits(right as u64)).to_bits(),
                ),
                SemanticOperationBinary::FDiv => u128::from(
                    (f64::from_bits(left as u64) / f64::from_bits(right as u64)).to_bits(),
                ),
                SemanticOperationBinary::And => left & right,
                SemanticOperationBinary::Or => left | right,
                SemanticOperationBinary::Xor => left ^ right,
                SemanticOperationBinary::Shl => {
                    left.wrapping_shl((right & u32::MAX as u128) as u32)
                }
                SemanticOperationBinary::LShr => {
                    left.wrapping_shr((right & u32::MAX as u128) as u32)
                }
                SemanticOperationBinary::RotateLeft => {
                    let shift = (right & u32::MAX as u128) as u32;
                    let width = *bits as u32;
                    if width == 0 {
                        left
                    } else {
                        let value = mask_to_bits(left, *bits);
                        let amount = shift % width;
                        mask_to_bits(
                            (value << amount) | (value >> ((width - amount) % width)),
                            *bits,
                        )
                    }
                }
                SemanticOperationBinary::RotateRight => {
                    let shift = (right & u32::MAX as u128) as u32;
                    let width = *bits as u32;
                    if width == 0 {
                        left
                    } else {
                        let value = mask_to_bits(left, *bits);
                        let amount = shift % width;
                        mask_to_bits(
                            (value >> amount) | (value << ((width - amount) % width)),
                            *bits,
                        )
                    }
                }
                SemanticOperationBinary::AShr => arithmetic_shift_right(left, right, *bits),
                SemanticOperationBinary::MinUnsigned => left.min(right),
                SemanticOperationBinary::MinSigned => match compare_signed(left, right, *bits) {
                    std::cmp::Ordering::Greater => right,
                    _ => left,
                },
                SemanticOperationBinary::MaxUnsigned => left.max(right),
                SemanticOperationBinary::MaxSigned => match compare_signed(left, right, *bits) {
                    std::cmp::Ordering::Less => right,
                    _ => left,
                },
                other => panic!("unsupported i386 test binary op: {other:?}"),
            };
            mask_to_bits(value, *bits)
        }
        SemanticExpression::Cast { op, arg, bits } => {
            let value = eval_expression(arg, registers, flags, memory, temporaries);
            match op {
                SemanticOperationCast::ZeroExtend
                | SemanticOperationCast::Bitcast
                | SemanticOperationCast::Truncate => mask_to_bits(value, *bits),
                SemanticOperationCast::SignExtend => {
                    mask_to_bits(sign_extend(value, arg_bits(arg), *bits), *bits)
                }
                SemanticOperationCast::FloatToInt => {
                    mask_to_bits(float_to_int_bits(value as u64, *bits), *bits)
                }
                SemanticOperationCast::IntToFloat => {
                    mask_to_bits(int_to_float_bits(value, arg_bits(arg), *bits), *bits)
                }
                other => panic!("unsupported i386 test cast op: {other:?}"),
            }
        }
        SemanticExpression::Compare {
            op, left, right, ..
        } => {
            let compare_bits = arg_bits(left);
            let left = left_value(left, registers, flags, memory, temporaries);
            let right = left_value(right, registers, flags, memory, temporaries);
            match op {
                SemanticOperationCompare::Eq => (left == right) as u128,
                SemanticOperationCompare::Ne => (left != right) as u128,
                SemanticOperationCompare::Ult => (left < right) as u128,
                SemanticOperationCompare::Ule => (left <= right) as u128,
                SemanticOperationCompare::Ugt => (left > right) as u128,
                SemanticOperationCompare::Uge => (left >= right) as u128,
                SemanticOperationCompare::Slt => {
                    (compare_signed(left, right, compare_bits) == std::cmp::Ordering::Less) as u128
                }
                SemanticOperationCompare::Sle => {
                    (compare_signed(left, right, compare_bits) != std::cmp::Ordering::Greater)
                        as u128
                }
                SemanticOperationCompare::Sgt => {
                    (compare_signed(left, right, compare_bits) == std::cmp::Ordering::Greater)
                        as u128
                }
                SemanticOperationCompare::Sge => {
                    (compare_signed(left, right, compare_bits) != std::cmp::Ordering::Less) as u128
                }
                SemanticOperationCompare::Unordered => {
                    (f64::from_bits(left as u64).is_nan() || f64::from_bits(right as u64).is_nan())
                        as u128
                }
                SemanticOperationCompare::Oeq => {
                    ordered_fp_compare(left as u64, right as u64, |l, r| l == r) as u128
                }
                SemanticOperationCompare::Olt => {
                    ordered_fp_compare(left as u64, right as u64, |l, r| l < r) as u128
                }
                other => panic!("unsupported i386 test compare op: {other:?}"),
            }
        }
        SemanticExpression::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            if eval_expression(condition, registers, flags, memory, temporaries) != 0 {
                eval_expression(when_true, registers, flags, memory, temporaries)
            } else {
                eval_expression(when_false, registers, flags, memory, temporaries)
            }
        }
        SemanticExpression::Extract { arg, lsb, bits } => mask_to_bits(
            eval_expression(arg, registers, flags, memory, temporaries) >> lsb,
            *bits,
        ),
        SemanticExpression::Concat { parts, bits } => {
            let mut value = 0u128;
            let mut shift = 0u16;
            for part in parts.iter().rev() {
                let part_bits = arg_bits(part);
                value |= eval_expression(part, registers, flags, memory, temporaries) << shift;
                shift += part_bits;
            }
            mask_to_bits(value, *bits)
        }
        SemanticExpression::Undefined { bits } | SemanticExpression::Poison { bits } => {
            mask_to_bits(0, *bits)
        }
        other => panic!("unsupported i386 test expression: {other:?}"),
    }
}

fn left_value(
    expression: &SemanticExpression,
    registers: &BTreeMap<String, u128>,
    flags: &BTreeMap<String, u128>,
    memory: &BTreeMap<u64, u8>,
    temporaries: &BTreeMap<u32, u128>,
) -> u128 {
    eval_expression(expression, registers, flags, memory, temporaries)
}

fn mask_for_bits(bits: u16) -> u128 {
    match bits {
        0 => 0,
        128 => u128::MAX,
        n => (1u128 << n) - 1,
    }
}

pub(crate) fn mask_to_bits(value: u128, bits: u16) -> u128 {
    value & mask_for_bits(bits)
}

fn read_flag(flags: &BTreeMap<String, u128>, name: &str) -> bool {
    flags.get(name).copied().unwrap_or_default() != 0
}

fn encode_modeled_eflags(flags: X86Flags) -> u32 {
    (1 << 1)
        | ((flags.cf as u32) << 0)
        | ((flags.pf as u32) << 2)
        | ((flags.af as u32) << 4)
        | ((flags.zf as u32) << 6)
        | ((flags.sf as u32) << 7)
        | ((flags.if_flag as u32) << 9)
        | ((flags.df as u32) << 10)
        | ((flags.of as u32) << 11)
}

fn arg_bits(expression: &SemanticExpression) -> u16 {
    match expression {
        SemanticExpression::Const { bits, .. }
        | SemanticExpression::Load { bits, .. }
        | SemanticExpression::Unary { bits, .. }
        | SemanticExpression::Binary { bits, .. }
        | SemanticExpression::Cast { bits, .. }
        | SemanticExpression::Compare { bits, .. }
        | SemanticExpression::Select { bits, .. }
        | SemanticExpression::Extract { bits, .. }
        | SemanticExpression::Concat { bits, .. }
        | SemanticExpression::Undefined { bits }
        | SemanticExpression::Poison { bits }
        | SemanticExpression::Intrinsic { bits, .. }
        | SemanticExpression::Architecture { bits, .. } => *bits,
        SemanticExpression::Read(location) => location.bits(),
    }
}

fn sign_extend(value: u128, from_bits: u16, to_bits: u16) -> u128 {
    let value = mask_to_bits(value, from_bits);
    if from_bits == 0 || to_bits <= from_bits {
        return mask_to_bits(value, to_bits);
    }
    let sign_mask = 1u128 << (from_bits - 1);
    if (value & sign_mask) == 0 {
        mask_to_bits(value, to_bits)
    } else {
        let extension = mask_for_bits(to_bits) ^ mask_for_bits(from_bits);
        mask_to_bits(value | extension, to_bits)
    }
}

fn compare_signed(left: u128, right: u128, bits: u16) -> std::cmp::Ordering {
    let left = mask_to_bits(left, bits);
    let right = mask_to_bits(right, bits);
    let sign_mask = if bits == 0 { 0 } else { 1u128 << (bits - 1) };
    let left_negative = (left & sign_mask) != 0;
    let right_negative = (right & sign_mask) != 0;
    match (left_negative, right_negative) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => left.cmp(&right),
    }
}

fn arithmetic_shift_right(left: u128, right: u128, bits: u16) -> u128 {
    if bits == 0 {
        return 0;
    }
    let shift = ((right & u32::MAX as u128) as u32).min(bits as u32);
    let value = mask_to_bits(left, bits);
    let logical = value >> shift;
    let sign_mask = 1u128 << (bits - 1);
    if (value & sign_mask) == 0 || shift == 0 {
        mask_to_bits(logical, bits)
    } else {
        let extension = mask_for_bits(bits) ^ mask_for_bits(bits - shift as u16);
        mask_to_bits(logical | extension, bits)
    }
}

fn ordered_fp_compare(left: u64, right: u64, predicate: impl FnOnce(f64, f64) -> bool) -> bool {
    let left = f64::from_bits(left);
    let right = f64::from_bits(right);
    if left.is_nan() || right.is_nan() {
        false
    } else {
        predicate(left, right)
    }
}

fn float_to_int_bits(value: u64, bits: u16) -> u128 {
    let float = f64::from_bits(value);
    if bits == 32 {
        if !float.is_finite() || float < i32::MIN as f64 || float > i32::MAX as f64 {
            i32::MIN as u32 as u128
        } else {
            (float.trunc() as i32 as u32) as u128
        }
    } else if bits == 64 {
        if !float.is_finite() || float < i64::MIN as f64 || float > i64::MAX as f64 {
            i64::MIN as u64 as u128
        } else {
            float.trunc() as i64 as u64 as u128
        }
    } else {
        panic!("unsupported float-to-int width: {bits}");
    }
}

fn int_to_float_bits(value: u128, from_bits: u16, bits: u16) -> u128 {
    assert_eq!(
        bits, 64,
        "only f64 int-to-float is supported in x86 fp tests"
    );
    let signed = if from_bits == 32 {
        (mask_to_bits(value, 32) as u32 as i32) as f64
    } else if from_bits == 64 {
        (mask_to_bits(value, 64) as u64 as i64) as f64
    } else {
        panic!("unsupported int-to-float source width: {from_bits}");
    };
    u128::from(signed.to_bits())
}

fn count_leading_zeros(value: u128, bits: u16) -> u16 {
    for bit in (0..bits).rev() {
        if ((value >> bit) & 1) != 0 {
            return bits - 1 - bit;
        }
    }
    bits
}

fn count_trailing_zeros(value: u128, bits: u16) -> u16 {
    for bit in 0..bits {
        if ((value >> bit) & 1) != 0 {
            return bit;
        }
    }
    bits
}

fn byte_swap(value: u128, bits: u16) -> u128 {
    let bytes = bits / 8;
    let mut swapped = 0u128;
    for index in 0..bytes {
        let byte = (value >> (index * 8)) & 0xff;
        let target_shift = ((bytes - 1 - index) * 8) as u32;
        swapped |= byte << target_shift;
    }
    swapped
}

fn written_state(semantics: &InstructionSemantics) -> (Vec<String>, Vec<String>) {
    let mut registers = Vec::new();
    let mut flags = Vec::new();
    for effect in &semantics.effects {
        if let SemanticEffect::Set { dst, .. } = effect {
            match dst {
                SemanticLocation::Register { name, .. } => {
                    let normalized = normalize_register_name(name);
                    if !registers.contains(&normalized) {
                        registers.push(normalized);
                    }
                }
                SemanticLocation::Flag { name, .. } => {
                    if !flags.contains(name)
                        && !matches!(
                            effect.expression(),
                            Some(
                                SemanticExpression::Undefined { .. }
                                    | SemanticExpression::Poison { .. }
                            )
                        )
                    {
                        flags.push(name.clone());
                    }
                }
                _ => {}
            }
        }
    }
    (registers, flags)
}

fn flag_value(flags: &X86Flags, name: &str) -> bool {
    match name {
        "cf" => flags.cf,
        "pf" => flags.pf,
        "af" => flags.af,
        "zf" => flags.zf,
        "sf" => flags.sf,
        "if" => flags.if_flag,
        "of" => flags.of,
        "df" => flags.df,
        other => panic!("unsupported modeled flag: {other}"),
    }
}

fn is_directly_undefined(expression: &SemanticExpression) -> bool {
    matches!(
        expression,
        SemanticExpression::Undefined { .. } | SemanticExpression::Poison { .. }
    )
}

fn mask_for_bits_wide(bits: u16) -> BigUint {
    if bits == 0 {
        BigUint::zero()
    } else {
        (BigUint::one() << (bits as usize)) - BigUint::one()
    }
}

pub(crate) fn mask_to_bits_wide(value: BigUint, bits: u16) -> BigUint {
    value & mask_for_bits_wide(bits)
}

fn shift_amount(value: &BigUint) -> usize {
    value.to_usize().expect("shift amount should fit in usize")
}

fn biguint_to_padded_le_bytes(value: &BigUint, byte_len: usize) -> Vec<u8> {
    let mut bytes = value.to_bytes_le();
    bytes.resize(byte_len, 0);
    bytes
}

fn sign_extend_wide(value: BigUint, from_bits: u16, to_bits: u16) -> BigUint {
    let value = mask_to_bits_wide(value, from_bits);
    if from_bits == 0 || to_bits <= from_bits {
        return mask_to_bits_wide(value, to_bits);
    }
    let sign_mask = BigUint::one() << ((from_bits - 1) as usize);
    if (&value & &sign_mask).is_zero() {
        mask_to_bits_wide(value, to_bits)
    } else {
        let extension = mask_for_bits_wide(to_bits) ^ mask_for_bits_wide(from_bits);
        mask_to_bits_wide(value | extension, to_bits)
    }
}

fn compare_signed_wide(left: &BigUint, right: &BigUint, bits: u16) -> std::cmp::Ordering {
    let left = mask_to_bits_wide(left.clone(), bits);
    let right = mask_to_bits_wide(right.clone(), bits);
    let sign_mask = if bits == 0 {
        BigUint::zero()
    } else {
        BigUint::one() << ((bits - 1) as usize)
    };
    let left_negative = !(&left & &sign_mask).is_zero();
    let right_negative = !(&right & &sign_mask).is_zero();
    match (left_negative, right_negative) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => left.cmp(&right),
    }
}

fn arithmetic_shift_right_wide(left: BigUint, right: BigUint, bits: u16) -> BigUint {
    if bits == 0 {
        return BigUint::zero();
    }
    let shift = shift_amount(&right).min(bits as usize);
    let value = mask_to_bits_wide(left, bits);
    let logical = &value >> shift;
    let sign_mask = BigUint::one() << ((bits - 1) as usize);
    if (&value & &sign_mask).is_zero() || shift == 0 {
        mask_to_bits_wide(logical, bits)
    } else {
        let extension = mask_for_bits_wide(bits) ^ mask_for_bits_wide(bits - shift as u16);
        mask_to_bits_wide(logical | extension, bits)
    }
}

fn count_leading_zeros_wide(value: BigUint, bits: u16) -> u16 {
    for bit in (0..bits).rev() {
        if !((&value >> (bit as usize)) & BigUint::one()).is_zero() {
            return bits - 1 - bit;
        }
    }
    bits
}

fn count_trailing_zeros_wide(value: BigUint, bits: u16) -> u16 {
    for bit in 0..bits {
        if !((&value >> (bit as usize)) & BigUint::one()).is_zero() {
            return bit;
        }
    }
    bits
}

fn load_le_value_wide(memory: &BTreeMap<u64, u8>, address: u64, bits: u16) -> BigUint {
    let byte_len = bits.div_ceil(8) as usize;
    let bytes = (0..byte_len)
        .map(|index| {
            memory
                .get(&(address + index as u64))
                .copied()
                .unwrap_or_default()
        })
        .collect::<Vec<_>>();
    mask_to_bits_wide(BigUint::from_bytes_le(&bytes), bits)
}

fn read_flag_wide(flags: &BTreeMap<String, BigUint>, name: &str) -> bool {
    !flags
        .get(name)
        .cloned()
        .unwrap_or_else(BigUint::zero)
        .is_zero()
}
