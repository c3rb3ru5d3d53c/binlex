use std::collections::BTreeMap;

use crate::controlflow::{Graph, Instruction};
use crate::disassemblers::capstone::Disassembler;
use crate::semantics::{
    InstructionSemantics, SemanticEffect, SemanticExpression, SemanticLocation,
    SemanticOperationBinary, SemanticOperationCast, SemanticOperationCompare,
    SemanticOperationUnary, SemanticStatus, SemanticTerminator,
};
use crate::{Architecture, Config};
use capstone::arch::x86::X86Reg;
use num_bigint::BigUint;
use num_traits::{One, ToPrimitive, Zero};
use unicorn_engine::Unicorn;
use unicorn_engine::unicorn_const::{Arch, Mode, Prot};
use unicorn_engine_sys::RegisterX86;

use super::super::common as x86_common;

const I386_CODE_ADDRESS: u64 = 0x1000;
const I386_CODE_PAGE_SIZE: u64 = 0x1000;
const I386_STACK_ADDRESS: u64 = 0x2000;
const I386_STACK_PAGE_SIZE: u64 = 0x1000;
const I386_DATA_ADDRESS: u64 = 0x3000;
const I386_DATA_PAGE_SIZE: u64 = 0x2000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct X86Flags {
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
pub(super) enum I386Register {
    Eax,
    Rax,
    Ebx,
    Ecx,
    Edx,
    Esi,
    Edi,
    Ebp,
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
pub(super) struct I386CpuState {
    pub registers: BTreeMap<String, u128>,
    pub eip: u32,
    pub eflags: u32,
    pub flags: X86Flags,
    pub memory: BTreeMap<u64, u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct I386Transition {
    pub pre: I386CpuState,
    pub post: I386CpuState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct I386Execution {
    transition: I386Transition,
    memory_writes: Vec<(u64, usize)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct I386CpuStateWide {
    registers: BTreeMap<String, BigUint>,
    eip: u32,
    eflags: u32,
    flags: X86Flags,
    memory: BTreeMap<u64, u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct I386TransitionWide {
    pre: I386CpuStateWide,
    post: I386CpuStateWide,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct I386ExecutionWide {
    transition: I386TransitionWide,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct I386Fixture {
    pub registers: Vec<(I386Register, u128)>,
    pub eflags: u32,
    pub memory: Vec<(u64, Vec<u8>)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct WideI386Fixture {
    pub base: I386Fixture,
    pub wide_registers: Vec<(I386Register, Vec<u8>)>,
}

pub(super) fn disassemble_x86_single(
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

pub(super) fn semantics(
    name: &str,
    architecture: Architecture,
    bytes: &[u8],
) -> InstructionSemantics {
    disassemble_x86_single(name, architecture, bytes)
        .semantics
        .expect("instruction should have semantics")
}

pub(super) fn assert_complete_semantics(name: &str, architecture: Architecture, bytes: &[u8]) {
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

pub(super) fn assert_i386_semantics_match_unicorn(name: &str, bytes: &[u8], fixture: I386Fixture) {
    assert_x86_semantics_match_unicorn(name, Architecture::I386, bytes, fixture);
}

pub(super) fn assert_amd64_semantics_match_unicorn(name: &str, bytes: &[u8], fixture: I386Fixture) {
    assert_x86_semantics_match_unicorn(name, Architecture::AMD64, bytes, fixture);
}

#[allow(dead_code)]
pub(super) fn assert_amd64_wide_semantics_match_unicorn(
    name: &str,
    bytes: &[u8],
    fixture: WideI386Fixture,
) {
    assert_amd64_semantics_match_unicorn_wide_impl(name, bytes, fixture);
}

pub(super) fn interpret_amd64_wide_semantics(
    name: &str,
    bytes: &[u8],
    fixture: WideI386Fixture,
) -> (BTreeMap<String, Vec<u8>>, X86Flags) {
    let semantics = semantics(name, Architecture::AMD64, bytes);
    let (written_registers, _) = written_state(&semantics);
    let tracked_registers = tracked_registers_for_wide_fixture(&fixture, &written_registers);
    let interpreted = interpret_amd64_semantics_wide(bytes, &semantics, &fixture, &tracked_registers);
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

pub(super) fn interpret_amd64_semantics(
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
    let unicorn =
        unicorn_x86_single_instruction(architecture, bytes, fixture, &interpreted.memory_writes);

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
            unicorn_value, interpreted_value,
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

fn unicorn_x86_single_instruction(
    architecture: Architecture,
    bytes: &[u8],
    fixture: I386Fixture,
    watched_memory: &[(u64, usize)],
) -> I386Execution {
    let mode = match architecture {
        Architecture::AMD64 => Mode::MODE_64,
        _ => Mode::MODE_32,
    };
    let mut emu = Unicorn::new(Arch::X86, mode).expect("unicorn x86 instance");
    emu.mem_map(I386_CODE_ADDRESS, I386_CODE_PAGE_SIZE, Prot::ALL)
        .expect("map i386 code page");
    emu.mem_map(I386_STACK_ADDRESS, I386_STACK_PAGE_SIZE, Prot::ALL)
        .expect("map i386 stack page");
    emu.mem_map(I386_DATA_ADDRESS, I386_DATA_PAGE_SIZE, Prot::ALL)
        .expect("map i386 data page");
    emu.mem_write(I386_CODE_ADDRESS, bytes)
        .expect("write i386 instruction bytes");
    for (register, value) in &fixture.registers {
        seed_unicorn_register(&mut emu, *register, *value);
    }
    for (address, bytes) in &fixture.memory {
        emu.mem_write(*address, bytes)
            .unwrap_or_else(|error| panic!("seed memory at 0x{address:x}: {error:?}"));
    }
    emu.reg_write(RegisterX86::EIP, I386_CODE_ADDRESS)
        .expect("seed eip");
    emu.reg_write(RegisterX86::EFLAGS, fixture.eflags as u64)
        .expect("seed eflags");

    let pre = snapshot_i386_state(architecture, &emu, fixture_memory_map(&fixture.memory));
    emu.emu_start(
        I386_CODE_ADDRESS,
        I386_CODE_ADDRESS + bytes.len() as u64,
        0,
        0,
    )
    .expect("execute one i386 instruction");
    let post = snapshot_i386_state(architecture, &emu, read_unicorn_memory(&emu, watched_memory));
    I386Execution {
        transition: I386Transition { pre, post },
        memory_writes: watched_memory.to_vec(),
    }
}

fn snapshot_i386_state(
    architecture: Architecture,
    emu: &Unicorn<'_, ()>,
    memory: BTreeMap<u64, u8>,
) -> I386CpuState {
    let registers = I386Register::all_for_arch(architecture)
        .into_iter()
        .map(|register| {
            (
                x86_common::reg_id_name(register.capstone_reg_id()),
                read_unicorn_register(emu, register),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let eip = emu.reg_read(RegisterX86::EIP).expect("read eip") as u32;
    let eflags = emu.reg_read(RegisterX86::EFLAGS).expect("read eflags") as u32;
    I386CpuState {
        registers,
        eip,
        eflags,
        flags: decode_eflags(eflags),
        memory,
    }
}

fn decode_eflags(eflags: u32) -> X86Flags {
    X86Flags {
        cf: (eflags & (1 << 0)) != 0,
        pf: (eflags & (1 << 2)) != 0,
        af: (eflags & (1 << 4)) != 0,
        zf: (eflags & (1 << 6)) != 0,
        sf: (eflags & (1 << 7)) != 0,
        if_flag: (eflags & (1 << 9)) != 0,
        of: (eflags & (1 << 11)) != 0,
        df: (eflags & (1 << 10)) != 0,
    }
}

fn seed_unicorn_register(emu: &mut Unicorn<'_, ()>, register: I386Register, value: u128) {
    match register.bit_width() {
        128 => emu
            .reg_write_long(register.unicorn_register(), &value.to_le_bytes())
            .unwrap_or_else(|error| panic!("seed {register:?}: {error:?}")),
        _ => emu
            .reg_write(register.unicorn_register(), value as u64)
            .unwrap_or_else(|error| panic!("seed {register:?}: {error:?}")),
    }
}

fn read_unicorn_register(emu: &Unicorn<'_, ()>, register: I386Register) -> u128 {
    match register.bit_width() {
        128 => {
            let bytes = emu
                .reg_read_long(register.unicorn_register())
                .unwrap_or_else(|error| panic!("read {register:?}: {error:?}"));
            let mut value_bytes = [0u8; 16];
            value_bytes.copy_from_slice(&bytes);
            u128::from_le_bytes(value_bytes)
        }
        _ => emu
            .reg_read(register.unicorn_register())
            .unwrap_or_else(|error| panic!("read {register:?}: {error:?}")) as u128,
    }
}

#[allow(dead_code)]
fn unicorn_amd64_single_instruction_wide(
    bytes: &[u8],
    fixture: &WideI386Fixture,
    tracked_registers: &[I386Register],
) -> I386ExecutionWide {
    let mut emu = Unicorn::new(Arch::X86, Mode::MODE_64).expect("unicorn x86 instance");
    emu.mem_map(I386_CODE_ADDRESS, I386_CODE_PAGE_SIZE, Prot::ALL)
        .expect("map code page");
    emu.mem_map(I386_STACK_ADDRESS, I386_STACK_PAGE_SIZE, Prot::ALL)
        .expect("map stack page");
    emu.mem_map(I386_DATA_ADDRESS, I386_DATA_PAGE_SIZE, Prot::ALL)
        .expect("map data page");
    emu.mem_write(I386_CODE_ADDRESS, bytes)
        .expect("write instruction bytes");
    for (register, value) in &fixture.base.registers {
        seed_unicorn_register(&mut emu, *register, *value);
    }
    for (register, value) in &fixture.wide_registers {
        emu.reg_write_long(register.unicorn_register(), value)
            .unwrap_or_else(|error| panic!("seed {register:?}: {error:?}"));
    }
    for (address, bytes) in &fixture.base.memory {
        emu.mem_write(*address, bytes)
            .unwrap_or_else(|error| panic!("seed memory at 0x{address:x}: {error:?}"));
    }
    emu.reg_write(RegisterX86::EIP, I386_CODE_ADDRESS)
        .expect("seed eip");
    emu.reg_write(RegisterX86::EFLAGS, fixture.base.eflags as u64)
        .expect("seed eflags");

    let pre = snapshot_x86_state_wide(&emu, tracked_registers, fixture_memory_map(&fixture.base.memory));
    emu.emu_start(I386_CODE_ADDRESS, I386_CODE_ADDRESS + bytes.len() as u64, 0, 0)
        .expect("execute one instruction");
    let post = snapshot_x86_state_wide(&emu, tracked_registers, BTreeMap::new());
    I386ExecutionWide {
        transition: I386TransitionWide { pre, post },
    }
}

#[allow(dead_code)]
fn snapshot_x86_state_wide(
    emu: &Unicorn<'_, ()>,
    tracked_registers: &[I386Register],
    memory: BTreeMap<u64, u8>,
) -> I386CpuStateWide {
    let registers = tracked_registers
        .iter()
        .map(|register| {
            (
                x86_common::reg_id_name(register.capstone_reg_id()),
                read_unicorn_register_wide(emu, *register),
            )
        })
        .collect();
    let eip = emu.reg_read(RegisterX86::EIP).expect("read eip") as u32;
    let eflags = emu.reg_read(RegisterX86::EFLAGS).expect("read eflags") as u32;
    I386CpuStateWide {
        registers,
        eip,
        eflags,
        flags: decode_eflags(eflags),
        memory,
    }
}

#[allow(dead_code)]
fn read_unicorn_register_wide(emu: &Unicorn<'_, ()>, register: I386Register) -> BigUint {
    match register.bit_width() {
        128 | 256 => BigUint::from_bytes_le(
            &emu.reg_read_long(register.unicorn_register())
                .unwrap_or_else(|error| panic!("read {register:?}: {error:?}")),
        ),
        _ => BigUint::from(
            emu.reg_read(register.unicorn_register())
                .unwrap_or_else(|error| panic!("read {register:?}: {error:?}")),
        ),
    }
}

fn interpret_i386_semantics(
    architecture: Architecture,
    bytes: &[u8],
    semantics: &InstructionSemantics,
    fixture: I386Fixture,
) -> I386Execution {
    assert_eq!(
        semantics.terminator,
        SemanticTerminator::FallThrough,
        "i386 conformance helper only supports fallthrough instructions"
    );

    let mut registers = I386Register::all_for_arch(architecture)
        .into_iter()
        .map(|register| (x86_common::reg_id_name(register.capstone_reg_id()), 0u128))
        .collect::<BTreeMap<_, _>>();
    for (register, value) in &fixture.registers {
        write_register_value(
            &mut registers,
            &x86_common::reg_id_name(register.capstone_reg_id()),
            *value as u128,
        );
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
    let post = I386CpuState {
        registers,
        eip: I386_CODE_ADDRESS as u32 + bytes.len() as u32,
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
        .map(|register| (x86_common::reg_id_name(register.capstone_reg_id()), BigUint::zero()))
        .collect::<BTreeMap<_, _>>();
    for (register, value) in &fixture.base.registers {
        write_register_value_wide(
            &mut registers,
            &x86_common::reg_id_name(register.capstone_reg_id()),
            BigUint::from(*value),
        );
    }
    for (register, bytes) in &fixture.wide_registers {
        write_register_value_wide(
            &mut registers,
            &x86_common::reg_id_name(register.capstone_reg_id()),
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
            SemanticLocation::Flag { name, .. } => flags.get(name).cloned().unwrap_or_else(BigUint::zero),
            SemanticLocation::Temporary { id, bits } => {
                mask_to_bits_wide(temporaries.get(id).cloned().unwrap_or_else(BigUint::zero), *bits)
            }
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
                SemanticOperationUnary::Not => mask_to_bits_wide(mask_for_bits_wide(*bits) ^ value, *bits),
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
                SemanticOperationUnary::PopCount => {
                    BigUint::from(value.to_bytes_le().iter().map(|byte| byte.count_ones() as u64).sum::<u64>())
                }
                other => panic!("unsupported wide unary op: {other:?}"),
            }
        }
        SemanticExpression::Binary { op, left, right, bits } => {
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
                SemanticOperationBinary::MinSigned => match compare_signed_wide(&left, &right, *bits) {
                    std::cmp::Ordering::Greater => right,
                    _ => left,
                },
                SemanticOperationBinary::MaxUnsigned => left.max(right),
                SemanticOperationBinary::MaxSigned => match compare_signed_wide(&left, &right, *bits) {
                    std::cmp::Ordering::Less => right,
                    _ => left,
                },
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
        SemanticExpression::Compare { op, left, right, .. } => {
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
        SemanticExpression::Select { condition, when_true, when_false, .. } => {
            if !eval_expression_wide(condition, registers, flags, memory, temporaries).is_zero() {
                eval_expression_wide(when_true, registers, flags, memory, temporaries)
            } else {
                eval_expression_wide(when_false, registers, flags, memory, temporaries)
            }
        }
        SemanticExpression::Extract { arg, lsb, bits } => {
            mask_to_bits_wide(eval_expression_wide(arg, registers, flags, memory, temporaries) >> (*lsb as usize), *bits)
        }
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
                SemanticOperationBinary::FAdd => {
                    u128::from((f64::from_bits(left as u64) + f64::from_bits(right as u64)).to_bits())
                }
                SemanticOperationBinary::FSub => {
                    u128::from((f64::from_bits(left as u64) - f64::from_bits(right as u64)).to_bits())
                }
                SemanticOperationBinary::FMul => {
                    u128::from((f64::from_bits(left as u64) * f64::from_bits(right as u64)).to_bits())
                }
                SemanticOperationBinary::FDiv => {
                    u128::from((f64::from_bits(left as u64) / f64::from_bits(right as u64)).to_bits())
                }
                SemanticOperationBinary::And => left & right,
                SemanticOperationBinary::Or => left | right,
                SemanticOperationBinary::Xor => left ^ right,
                SemanticOperationBinary::Shl => {
                    left.wrapping_shl((right & u32::MAX as u128) as u32)
                }
                SemanticOperationBinary::LShr => {
                    left.wrapping_shr((right & u32::MAX as u128) as u32)
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
                SemanticOperationCompare::Oeq => ordered_fp_compare(left as u64, right as u64, |l, r| l == r)
                    as u128,
                SemanticOperationCompare::Olt => ordered_fp_compare(left as u64, right as u64, |l, r| l < r)
                    as u128,
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

fn mask_to_bits(value: u128, bits: u16) -> u128 {
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
        | SemanticExpression::Intrinsic { bits, .. } => *bits,
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
    assert_eq!(bits, 64, "only f64 int-to-float is supported in x86 fp tests");
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

fn fixture_memory_map(regions: &[(u64, Vec<u8>)]) -> BTreeMap<u64, u8> {
    let mut memory = BTreeMap::new();
    for (address, bytes) in regions {
        for (offset, byte) in bytes.iter().copied().enumerate() {
            memory.insert(address + offset as u64, byte);
        }
    }
    memory
}

fn value_to_le_bytes(value: u128, bits: u16) -> Vec<u8> {
    let byte_len = bits.div_ceil(8) as usize;
    (0..byte_len)
        .map(|index| ((value >> (index * 8)) & 0xff) as u8)
        .collect()
}

fn load_le_value(memory: &BTreeMap<u64, u8>, address: u64, bits: u16) -> u128 {
    let byte_len = bits.div_ceil(8) as usize;
    let mut value = 0u128;
    for index in 0..byte_len {
        let byte = memory
            .get(&(address + index as u64))
            .copied()
            .unwrap_or_default() as u128;
        value |= byte << (index * 8);
    }
    mask_to_bits(value, bits)
}

fn load_le_bytes(memory: &BTreeMap<u64, u8>, address: u64, bits: u16) -> Vec<u8> {
    let byte_len = bits.div_ceil(8) as usize;
    (0..byte_len)
        .map(|index| {
            memory
                .get(&(address + index as u64))
                .copied()
                .unwrap_or_default()
        })
        .collect()
}

fn read_unicorn_memory(emu: &Unicorn<'_, ()>, ranges: &[(u64, usize)]) -> BTreeMap<u64, u8> {
    let mut memory = BTreeMap::new();
    for (address, size) in ranges {
        let bytes = emu
            .mem_read_as_vec(*address, *size)
            .unwrap_or_else(|error| panic!("read memory at 0x{address:x}: {error:?}"));
        for (offset, byte) in bytes.into_iter().enumerate() {
            memory.insert(address + offset as u64, byte);
        }
    }
    memory
}

fn read_register_value(registers: &BTreeMap<String, u128>, name: &str, bits: u16) -> u128 {
    if let Some(value) = registers.get(name) {
        return mask_to_bits(*value, bits);
    }

    let eax_name = x86_common::reg_id_name(X86Reg::X86_REG_EAX as u16);
    let rax_name = x86_common::reg_id_name(X86Reg::X86_REG_RAX as u16);
    let eax_value = registers.get(&eax_name).copied().unwrap_or_default();
    let ebx_name = x86_common::reg_id_name(X86Reg::X86_REG_EBX as u16);
    let rbx_name = x86_common::reg_id_name(X86Reg::X86_REG_RBX as u16);
    let ecx_name = x86_common::reg_id_name(X86Reg::X86_REG_ECX as u16);
    let rcx_name = x86_common::reg_id_name(X86Reg::X86_REG_RCX as u16);
    let edx_name = x86_common::reg_id_name(X86Reg::X86_REG_EDX as u16);
    let rdx_name = x86_common::reg_id_name(X86Reg::X86_REG_RDX as u16);
    let esi_name = x86_common::reg_id_name(X86Reg::X86_REG_ESI as u16);
    let rsi_name = x86_common::reg_id_name(X86Reg::X86_REG_RSI as u16);
    let edi_name = x86_common::reg_id_name(X86Reg::X86_REG_EDI as u16);
    let rdi_name = x86_common::reg_id_name(X86Reg::X86_REG_RDI as u16);
    let ebp_name = x86_common::reg_id_name(X86Reg::X86_REG_EBP as u16);
    let rbp_name = x86_common::reg_id_name(X86Reg::X86_REG_RBP as u16);
    let esp_name = x86_common::reg_id_name(X86Reg::X86_REG_ESP as u16);
    let rsp_name = x86_common::reg_id_name(X86Reg::X86_REG_RSP as u16);

    if name == x86_common::reg_id_name(X86Reg::X86_REG_AX as u16) {
        return mask_to_bits(eax_value, 16);
    }
    if name == x86_common::reg_id_name(X86Reg::X86_REG_AH as u16) {
        return mask_to_bits(eax_value >> 8, 8);
    }
    if name == x86_common::reg_id_name(X86Reg::X86_REG_AL as u16) {
        return mask_to_bits(eax_value, 8);
    }
    if name == rax_name {
        return mask_to_bits(registers.get(&eax_name).copied().unwrap_or_default(), bits);
    }
    if name == eax_name {
        return mask_to_bits(registers.get(&rax_name).copied().unwrap_or_default(), bits);
    }
    for (wide, narrow) in [
        (&rbx_name, &ebx_name),
        (&rcx_name, &ecx_name),
        (&rdx_name, &edx_name),
        (&rsi_name, &esi_name),
        (&rdi_name, &edi_name),
        (&rbp_name, &ebp_name),
    ] {
        if name == *wide {
            return mask_to_bits(registers.get(narrow).copied().unwrap_or_default(), bits);
        }
        if name == *narrow {
            return mask_to_bits(registers.get(wide).copied().unwrap_or_default(), bits);
        }
    }
    if name == rsp_name {
        return mask_to_bits(registers.get(&esp_name).copied().unwrap_or_default(), bits);
    }
    if name == esp_name {
        return mask_to_bits(registers.get(&rsp_name).copied().unwrap_or_default(), bits);
    }

    panic!("unknown register read: {name}");
}

fn write_register_value(registers: &mut BTreeMap<String, u128>, name: &str, value: u128) {
    let eax_name = x86_common::reg_id_name(X86Reg::X86_REG_EAX as u16);
    let rax_name = x86_common::reg_id_name(X86Reg::X86_REG_RAX as u16);
    let ebx_name = x86_common::reg_id_name(X86Reg::X86_REG_EBX as u16);
    let rbx_name = x86_common::reg_id_name(X86Reg::X86_REG_RBX as u16);
    let ecx_name = x86_common::reg_id_name(X86Reg::X86_REG_ECX as u16);
    let rcx_name = x86_common::reg_id_name(X86Reg::X86_REG_RCX as u16);
    let edx_name = x86_common::reg_id_name(X86Reg::X86_REG_EDX as u16);
    let rdx_name = x86_common::reg_id_name(X86Reg::X86_REG_RDX as u16);
    let esi_name = x86_common::reg_id_name(X86Reg::X86_REG_ESI as u16);
    let rsi_name = x86_common::reg_id_name(X86Reg::X86_REG_RSI as u16);
    let edi_name = x86_common::reg_id_name(X86Reg::X86_REG_EDI as u16);
    let rdi_name = x86_common::reg_id_name(X86Reg::X86_REG_RDI as u16);
    let ebp_name = x86_common::reg_id_name(X86Reg::X86_REG_EBP as u16);
    let rbp_name = x86_common::reg_id_name(X86Reg::X86_REG_RBP as u16);
    let esp_name = x86_common::reg_id_name(X86Reg::X86_REG_ESP as u16);
    let rsp_name = x86_common::reg_id_name(X86Reg::X86_REG_RSP as u16);
    if name == x86_common::reg_id_name(X86Reg::X86_REG_AX as u16) {
        let current = registers.get(&eax_name).copied().unwrap_or_default();
        let next = (current & !0xffff) | mask_to_bits(value, 16);
        registers.insert(eax_name, next);
        return;
    }
    if name == x86_common::reg_id_name(X86Reg::X86_REG_AL as u16) {
        let current = registers.get(&eax_name).copied().unwrap_or_default();
        let next = (current & !0xff) | mask_to_bits(value, 8);
        registers.insert(eax_name, next);
        return;
    }
    if name == x86_common::reg_id_name(X86Reg::X86_REG_AH as u16) {
        let current = registers.get(&eax_name).copied().unwrap_or_default();
        let next = (current & !(0xff << 8)) | (mask_to_bits(value, 8) << 8);
        registers.insert(eax_name, next);
        return;
    }
    if name == eax_name {
        let masked = mask_to_bits(value, 32);
        registers.insert(eax_name, masked);
        if registers.contains_key(&rax_name) {
            registers.insert(rax_name, masked);
        }
        return;
    }
    if name == rax_name {
        let masked = mask_to_bits(value, 64);
        registers.insert(rax_name, masked);
        if registers.contains_key(&eax_name) {
            registers.insert(eax_name, mask_to_bits(masked, 32));
        }
        return;
    }
    for (wide, narrow) in [
        (&rbx_name, &ebx_name),
        (&rcx_name, &ecx_name),
        (&rdx_name, &edx_name),
        (&rsi_name, &esi_name),
        (&rdi_name, &edi_name),
        (&rbp_name, &ebp_name),
    ] {
        if name == *narrow {
            let masked = mask_to_bits(value, 32);
            registers.insert((*narrow).clone(), masked);
            if registers.contains_key(wide) {
                registers.insert((*wide).clone(), masked);
            }
            return;
        }
        if name == *wide {
            let masked = mask_to_bits(value, 64);
            registers.insert((*wide).clone(), masked);
            if registers.contains_key(narrow) {
                registers.insert((*narrow).clone(), mask_to_bits(masked, 32));
            }
            return;
        }
    }
    if name == esp_name {
        let masked = mask_to_bits(value, 32);
        registers.insert(esp_name, masked);
        if registers.contains_key(&rsp_name) {
            registers.insert(rsp_name, masked);
        }
        return;
    }
    if name == rsp_name {
        let masked = mask_to_bits(value, 64);
        registers.insert(rsp_name, masked);
        if registers.contains_key(&esp_name) {
            registers.insert(esp_name, mask_to_bits(masked, 32));
        }
        return;
    }

    registers.insert(name.to_string(), value);
}

fn normalize_register_name(name: &str) -> String {
    if name == x86_common::reg_id_name(X86Reg::X86_REG_AX as u16)
        || name == x86_common::reg_id_name(X86Reg::X86_REG_AH as u16)
        || name == x86_common::reg_id_name(X86Reg::X86_REG_AL as u16)
    {
        return x86_common::reg_id_name(X86Reg::X86_REG_EAX as u16);
    }
    if name == x86_common::reg_id_name(X86Reg::X86_REG_RAX as u16) {
        return x86_common::reg_id_name(X86Reg::X86_REG_RAX as u16);
    }
    name.to_string()
}

fn is_directly_undefined(expression: &SemanticExpression) -> bool {
    matches!(
        expression,
        SemanticExpression::Undefined { .. } | SemanticExpression::Poison { .. }
    )
}

fn register_by_name(name: &str) -> Option<I386Register> {
    [
        I386Register::Eax,
        I386Register::Rax,
        I386Register::Ebx,
        I386Register::Ecx,
        I386Register::Edx,
        I386Register::Esi,
        I386Register::Edi,
        I386Register::Ebp,
        I386Register::Esp,
        I386Register::Rsp,
        I386Register::Xmm0,
        I386Register::Xmm1,
        I386Register::Xmm2,
        I386Register::Ymm0,
        I386Register::Ymm1,
        I386Register::Ymm2,
    ]
    .into_iter()
    .find(|register| x86_common::reg_id_name(register.capstone_reg_id()) == name)
}

fn mask_for_bits_wide(bits: u16) -> BigUint {
    if bits == 0 {
        BigUint::zero()
    } else {
        (BigUint::one() << (bits as usize)) - BigUint::one()
    }
}

fn mask_to_bits_wide(value: BigUint, bits: u16) -> BigUint {
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
        .map(|index| memory.get(&(address + index as u64)).copied().unwrap_or_default())
        .collect::<Vec<_>>();
    mask_to_bits_wide(BigUint::from_bytes_le(&bytes), bits)
}

fn read_flag_wide(flags: &BTreeMap<String, BigUint>, name: &str) -> bool {
    !flags.get(name).cloned().unwrap_or_else(BigUint::zero).is_zero()
}

fn read_register_value_wide(registers: &BTreeMap<String, BigUint>, name: &str, bits: u16) -> BigUint {
    if let Some(value) = registers.get(name) {
        return mask_to_bits_wide(value.clone(), bits);
    }

    let eax_name = x86_common::reg_id_name(X86Reg::X86_REG_EAX as u16);
    let rax_name = x86_common::reg_id_name(X86Reg::X86_REG_RAX as u16);
    let eax_value = registers.get(&eax_name).cloned().unwrap_or_else(BigUint::zero);
    let esp_name = x86_common::reg_id_name(X86Reg::X86_REG_ESP as u16);
    let rsp_name = x86_common::reg_id_name(X86Reg::X86_REG_RSP as u16);

    if name == x86_common::reg_id_name(X86Reg::X86_REG_AX as u16) {
        return mask_to_bits_wide(eax_value, 16);
    }
    if name == x86_common::reg_id_name(X86Reg::X86_REG_AH as u16) {
        return mask_to_bits_wide(eax_value >> 8usize, 8);
    }
    if name == x86_common::reg_id_name(X86Reg::X86_REG_AL as u16) {
        return mask_to_bits_wide(eax_value, 8);
    }
    if name == rax_name {
        return mask_to_bits_wide(registers.get(&eax_name).cloned().unwrap_or_else(BigUint::zero), bits);
    }
    if name == eax_name {
        return mask_to_bits_wide(registers.get(&rax_name).cloned().unwrap_or_else(BigUint::zero), bits);
    }
    if name == rsp_name {
        return mask_to_bits_wide(registers.get(&esp_name).cloned().unwrap_or_else(BigUint::zero), bits);
    }
    if name == esp_name {
        return mask_to_bits_wide(registers.get(&rsp_name).cloned().unwrap_or_else(BigUint::zero), bits);
    }
    registers.get(name).cloned().unwrap_or_else(BigUint::zero)
}

fn write_register_value_wide(registers: &mut BTreeMap<String, BigUint>, name: &str, value: BigUint) {
    let eax_name = x86_common::reg_id_name(X86Reg::X86_REG_EAX as u16);
    let rax_name = x86_common::reg_id_name(X86Reg::X86_REG_RAX as u16);
    let esp_name = x86_common::reg_id_name(X86Reg::X86_REG_ESP as u16);
    let rsp_name = x86_common::reg_id_name(X86Reg::X86_REG_RSP as u16);
    if name == x86_common::reg_id_name(X86Reg::X86_REG_AX as u16) {
        let current = registers.get(&eax_name).cloned().unwrap_or_else(BigUint::zero);
        let next = ((&current >> 16usize) << 16usize) | mask_to_bits_wide(value, 16);
        registers.insert(eax_name, next);
        return;
    }
    if name == x86_common::reg_id_name(X86Reg::X86_REG_AL as u16) {
        let current = registers.get(&eax_name).cloned().unwrap_or_else(BigUint::zero);
        let next = ((&current >> 8usize) << 8usize) | mask_to_bits_wide(value, 8);
        registers.insert(eax_name, next);
        return;
    }
    if name == x86_common::reg_id_name(X86Reg::X86_REG_AH as u16) {
        let current = registers.get(&eax_name).cloned().unwrap_or_else(BigUint::zero);
        let low = mask_to_bits_wide(current.clone(), 8);
        let high = (&current >> 16usize) << 16usize;
        registers.insert(
            eax_name,
            high | (mask_to_bits_wide(value, 8) << 8usize) | low,
        );
        return;
    }
    if name == eax_name {
        let masked = mask_to_bits_wide(value, 32);
        registers.insert(eax_name.clone(), masked.clone());
        if registers.contains_key(&rax_name) {
            registers.insert(rax_name, masked);
        }
        return;
    }
    if name == rax_name {
        let masked = mask_to_bits_wide(value, 64);
        registers.insert(rax_name.clone(), masked.clone());
        if registers.contains_key(&eax_name) {
            registers.insert(eax_name, mask_to_bits_wide(masked, 32));
        }
        return;
    }
    if name == esp_name {
        let masked = mask_to_bits_wide(value, 32);
        registers.insert(esp_name.clone(), masked.clone());
        if registers.contains_key(&rsp_name) {
            registers.insert(rsp_name, masked);
        }
        return;
    }
    if name == rsp_name {
        let masked = mask_to_bits_wide(value, 64);
        registers.insert(rsp_name.clone(), masked.clone());
        if registers.contains_key(&esp_name) {
            registers.insert(esp_name, mask_to_bits_wide(masked, 32));
        }
        return;
    }
    registers.insert(name.to_string(), value);
}

impl I386Register {
    fn all_for_arch(architecture: Architecture) -> Vec<Self> {
    let mut registers = vec![
            Self::Eax,
            Self::Ebx,
            Self::Ecx,
            Self::Edx,
            Self::Esi,
            Self::Edi,
            Self::Ebp,
            Self::Esp,
            Self::Xmm0,
            Self::Xmm1,
            Self::Xmm2,
        ];
        if matches!(architecture, Architecture::AMD64) {
            registers.push(Self::Rax);
            registers.push(Self::Rsp);
        }
        registers
    }

    fn capstone_reg_id(self) -> u16 {
        match self {
            Self::Eax => X86Reg::X86_REG_EAX as u16,
            Self::Rax => X86Reg::X86_REG_RAX as u16,
            Self::Ebx => X86Reg::X86_REG_EBX as u16,
            Self::Ecx => X86Reg::X86_REG_ECX as u16,
            Self::Edx => X86Reg::X86_REG_EDX as u16,
            Self::Esi => X86Reg::X86_REG_ESI as u16,
            Self::Edi => X86Reg::X86_REG_EDI as u16,
            Self::Ebp => X86Reg::X86_REG_EBP as u16,
            Self::Esp => X86Reg::X86_REG_ESP as u16,
            Self::Rsp => X86Reg::X86_REG_RSP as u16,
            Self::Xmm0 => X86Reg::X86_REG_XMM0 as u16,
            Self::Xmm1 => X86Reg::X86_REG_XMM1 as u16,
            Self::Xmm2 => X86Reg::X86_REG_XMM2 as u16,
            Self::Ymm0 => X86Reg::X86_REG_YMM0 as u16,
            Self::Ymm1 => X86Reg::X86_REG_YMM1 as u16,
            Self::Ymm2 => X86Reg::X86_REG_YMM2 as u16,
        }
    }

    fn unicorn_register(self) -> RegisterX86 {
        match self {
            Self::Eax => RegisterX86::EAX,
            Self::Rax => RegisterX86::RAX,
            Self::Ebx => RegisterX86::EBX,
            Self::Ecx => RegisterX86::ECX,
            Self::Edx => RegisterX86::EDX,
            Self::Esi => RegisterX86::ESI,
            Self::Edi => RegisterX86::EDI,
            Self::Ebp => RegisterX86::EBP,
            Self::Esp => RegisterX86::ESP,
            Self::Rsp => RegisterX86::RSP,
            Self::Xmm0 => RegisterX86::XMM0,
            Self::Xmm1 => RegisterX86::XMM1,
            Self::Xmm2 => RegisterX86::XMM2,
            Self::Ymm0 => RegisterX86::YMM0,
            Self::Ymm1 => RegisterX86::YMM1,
            Self::Ymm2 => RegisterX86::YMM2,
        }
    }

    fn bit_width(self) -> u16 {
        match self {
            Self::Rax | Self::Rsp => 64,
            Self::Xmm0 | Self::Xmm1 | Self::Xmm2 => 128,
            Self::Ymm0 | Self::Ymm1 | Self::Ymm2 => 256,
            _ => 32,
        }
    }
}
