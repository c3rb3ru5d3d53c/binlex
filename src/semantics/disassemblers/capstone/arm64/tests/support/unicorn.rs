use std::collections::BTreeMap;
use std::collections::BTreeSet;

use capstone::arch::arm64::Arm64Reg;
use unicorn_engine::Unicorn;
use unicorn_engine::unicorn_const::{Arch, Mode, Prot};
use unicorn_engine_sys::RegisterARM64;

use super::fixtures::{Arm64CpuState, Arm64Execution, Arm64Fixture, Arm64Transition};

pub(crate) const ARM64_CODE_ADDRESS: u64 = 0x1000;
const ARM64_PAGE_SIZE: u64 = 0x1000;
const ARM64_STACK_ADDRESS: u64 = 0x2000;
const ARM64_VECTOR_INPUT_ADDRESS: u64 = 0x3000;
const ARM64_VECTOR_OUTPUT_ADDRESS: u64 = 0x4000;
const TPIDR_EL0_SEMANTIC_NAME: &str = "arm64_sysreg_tpidr_el0";
const FPCR_SEMANTIC_NAME: &str = "arm64_sysreg_fpcr";

pub(crate) fn unicorn_arm64_execution(
    name: &str,
    bytes: &[u8],
    fixture: &Arm64Fixture,
    tracked_registers: &[String],
    watched_memory: &[(u64, usize)],
    watched_vector_registers: &[String],
) -> Arm64Execution {
    let mut emu = Unicorn::new(Arch::ARM64, Mode::ARM).expect("unicorn arm64 instance");
    let use_vector_program = uses_vector_program(fixture, watched_vector_registers);
    emu.mem_map(ARM64_CODE_ADDRESS, ARM64_PAGE_SIZE, Prot::ALL)
        .expect("map arm64 code page");
    emu.mem_map(ARM64_STACK_ADDRESS, ARM64_PAGE_SIZE, Prot::ALL)
        .expect("map arm64 stack page");
    if use_vector_program {
        emu.mem_map(ARM64_VECTOR_INPUT_ADDRESS, ARM64_PAGE_SIZE, Prot::ALL)
            .expect("map arm64 vector input page");
        emu.mem_map(ARM64_VECTOR_OUTPUT_ADDRESS, ARM64_PAGE_SIZE, Prot::ALL)
            .expect("map arm64 vector output page");
    }
    map_arm64_data_pages(&mut emu, fixture, watched_memory);
    let program = build_arm64_program(bytes, fixture, watched_vector_registers);
    emu.mem_write(ARM64_CODE_ADDRESS, &program)
        .expect("write arm64 instruction bytes");
    emu.reg_write(RegisterARM64::PC, ARM64_CODE_ADDRESS)
        .expect("seed pc");
    emu.reg_write(
        RegisterARM64::SP,
        ARM64_STACK_ADDRESS + ARM64_PAGE_SIZE - 0x10,
    )
    .expect("seed sp");
    if use_vector_program {
        emu.reg_write(RegisterARM64::X27, ARM64_VECTOR_INPUT_ADDRESS)
            .expect("seed vector input pointer");
        emu.reg_write(RegisterARM64::X28, ARM64_VECTOR_OUTPUT_ADDRESS)
            .expect("seed vector output pointer");
        seed_vector_fixture_memory(&mut emu, fixture);
    }

    for (register, value) in &fixture.registers {
        if matches!(*register, "n" | "z" | "c" | "v") {
            write_arm64_flag(&mut emu, register, *value != 0);
        } else if matches!(*register, "v0" | "v1" | "q0" | "q1") {
            continue;
        } else {
            write_arm64_register(&mut emu, register, *value);
        }
    }
    for (address, bytes) in &fixture.memory {
        emu.mem_write(*address, bytes)
            .unwrap_or_else(|error| panic!("seed memory at 0x{address:x}: {error:?}"));
    }

    let pre = snapshot_arm64_state(&emu, tracked_registers, fixture_memory_map(&fixture.memory));
    let instruction_count = if use_vector_program {
        (program.len() / 4) as usize
    } else {
        1
    };
    emu.emu_start(
        ARM64_CODE_ADDRESS,
        ARM64_CODE_ADDRESS + program.len() as u64,
        0,
        instruction_count,
    )
    .unwrap_or_else(|error| panic!("{name}: execute arm64 instruction: {error:?}"));
    let mut all_watched_memory = watched_memory.to_vec();
    all_watched_memory.extend(watched_vector_memory_ranges(watched_vector_registers));
    let mut post = snapshot_arm64_state(
        &emu,
        tracked_registers,
        read_unicorn_memory(&emu, &all_watched_memory),
    );
    if use_vector_program {
        post.pc = ARM64_CODE_ADDRESS + bytes.len() as u64;
    }

    Arm64Execution {
        transition: Arm64Transition { pre, post },
        memory_writes: all_watched_memory,
    }
}

pub(crate) fn semantic_name_for_arch_register(register: &str) -> String {
    if matches!(register, "n" | "z" | "c" | "v") {
        return register.to_string();
    }
    if register == "tpidr_el0" {
        return TPIDR_EL0_SEMANTIC_NAME.to_string();
    }
    if register == "fpcr" {
        return FPCR_SEMANTIC_NAME.to_string();
    }
    let reg = match register {
        "h0" => Arm64Reg::ARM64_REG_H0,
        "d0" => Arm64Reg::ARM64_REG_D0,
        "d1" => Arm64Reg::ARM64_REG_D1,
        "d2" => Arm64Reg::ARM64_REG_D2,
        "d3" => Arm64Reg::ARM64_REG_D3,
        "s0" => Arm64Reg::ARM64_REG_S0,
        "s1" => Arm64Reg::ARM64_REG_S1,
        "q0" | "v0" => Arm64Reg::ARM64_REG_V0,
        "q1" | "v1" => Arm64Reg::ARM64_REG_V1,
        "q2" | "v2" => Arm64Reg::ARM64_REG_V2,
        "q3" | "v3" => Arm64Reg::ARM64_REG_V3,
        "w0" => Arm64Reg::ARM64_REG_W0,
        "w1" => Arm64Reg::ARM64_REG_W1,
        "w2" => Arm64Reg::ARM64_REG_W2,
        "w3" => Arm64Reg::ARM64_REG_W3,
        "w4" => Arm64Reg::ARM64_REG_W4,
        "w5" => Arm64Reg::ARM64_REG_W5,
        "w6" => Arm64Reg::ARM64_REG_W6,
        "w7" => Arm64Reg::ARM64_REG_W7,
        "w8" => Arm64Reg::ARM64_REG_W8,
        "w9" => Arm64Reg::ARM64_REG_W9,
        "w10" => Arm64Reg::ARM64_REG_W10,
        "w11" => Arm64Reg::ARM64_REG_W11,
        "w12" => Arm64Reg::ARM64_REG_W12,
        "w13" => Arm64Reg::ARM64_REG_W13,
        "w14" => Arm64Reg::ARM64_REG_W14,
        "w15" => Arm64Reg::ARM64_REG_W15,
        "w16" => Arm64Reg::ARM64_REG_W16,
        "w17" => Arm64Reg::ARM64_REG_W17,
        "w18" => Arm64Reg::ARM64_REG_W18,
        "w19" => Arm64Reg::ARM64_REG_W19,
        "w20" => Arm64Reg::ARM64_REG_W20,
        "w21" => Arm64Reg::ARM64_REG_W21,
        "w22" => Arm64Reg::ARM64_REG_W22,
        "w23" => Arm64Reg::ARM64_REG_W23,
        "w24" => Arm64Reg::ARM64_REG_W24,
        "w25" => Arm64Reg::ARM64_REG_W25,
        "w26" => Arm64Reg::ARM64_REG_W26,
        "w27" => Arm64Reg::ARM64_REG_W27,
        "w28" => Arm64Reg::ARM64_REG_W28,
        "w29" => Arm64Reg::ARM64_REG_W29,
        "w30" => Arm64Reg::ARM64_REG_W30,
        "x0" => Arm64Reg::ARM64_REG_X0,
        "x1" => Arm64Reg::ARM64_REG_X1,
        "x2" => Arm64Reg::ARM64_REG_X2,
        "x3" => Arm64Reg::ARM64_REG_X3,
        "x4" => Arm64Reg::ARM64_REG_X4,
        "x5" => Arm64Reg::ARM64_REG_X5,
        "x6" => Arm64Reg::ARM64_REG_X6,
        "x7" => Arm64Reg::ARM64_REG_X7,
        "x8" => Arm64Reg::ARM64_REG_X8,
        "x9" => Arm64Reg::ARM64_REG_X9,
        "x10" => Arm64Reg::ARM64_REG_X10,
        "x11" => Arm64Reg::ARM64_REG_X11,
        "x12" => Arm64Reg::ARM64_REG_X12,
        "x13" => Arm64Reg::ARM64_REG_X13,
        "x14" => Arm64Reg::ARM64_REG_X14,
        "x15" => Arm64Reg::ARM64_REG_X15,
        "x16" => Arm64Reg::ARM64_REG_X16,
        "x17" => Arm64Reg::ARM64_REG_X17,
        "x18" => Arm64Reg::ARM64_REG_X18,
        "x19" => Arm64Reg::ARM64_REG_X19,
        "x20" => Arm64Reg::ARM64_REG_X20,
        "x21" => Arm64Reg::ARM64_REG_X21,
        "x22" => Arm64Reg::ARM64_REG_X22,
        "x23" => Arm64Reg::ARM64_REG_X23,
        "x24" => Arm64Reg::ARM64_REG_X24,
        "x25" => Arm64Reg::ARM64_REG_X25,
        "x26" => Arm64Reg::ARM64_REG_X26,
        "x27" => Arm64Reg::ARM64_REG_X27,
        "x28" => Arm64Reg::ARM64_REG_X28,
        "x29" => Arm64Reg::ARM64_REG_X29,
        "x30" => Arm64Reg::ARM64_REG_X30,
        "sp" => Arm64Reg::ARM64_REG_SP,
        other => panic!("unsupported arm64 fixture register: {other}"),
    };
    format!("reg_{}", reg as u32)
}

fn semantic_name_to_unicorn_register(name: &str) -> RegisterARM64 {
    match name {
        "n" | "z" | "c" | "v" => RegisterARM64::NZCV,
        TPIDR_EL0_SEMANTIC_NAME => RegisterARM64::TPIDR_EL0,
        FPCR_SEMANTIC_NAME => RegisterARM64::FPCR,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_W0 as u32) => RegisterARM64::W0,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_W1 as u32) => RegisterARM64::W1,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_W2 as u32) => RegisterARM64::W2,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_W3 as u32) => RegisterARM64::W3,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_W4 as u32) => RegisterARM64::W4,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_W5 as u32) => RegisterARM64::W5,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_W6 as u32) => RegisterARM64::W6,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_W7 as u32) => RegisterARM64::W7,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_W8 as u32) => RegisterARM64::W8,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_W9 as u32) => RegisterARM64::W9,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_W10 as u32) => RegisterARM64::W10,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_W11 as u32) => RegisterARM64::W11,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_W12 as u32) => RegisterARM64::W12,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_W13 as u32) => RegisterARM64::W13,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_W14 as u32) => RegisterARM64::W14,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_W15 as u32) => RegisterARM64::W15,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_W16 as u32) => RegisterARM64::W16,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_W17 as u32) => RegisterARM64::W17,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_W18 as u32) => RegisterARM64::W18,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_W19 as u32) => RegisterARM64::W19,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_W20 as u32) => RegisterARM64::W20,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_W21 as u32) => RegisterARM64::W21,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_W22 as u32) => RegisterARM64::W22,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_W23 as u32) => RegisterARM64::W23,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_W24 as u32) => RegisterARM64::W24,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_W25 as u32) => RegisterARM64::W25,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_W26 as u32) => RegisterARM64::W26,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_W27 as u32) => RegisterARM64::W27,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_W28 as u32) => RegisterARM64::W28,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_W29 as u32) => RegisterARM64::W29,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_W30 as u32) => RegisterARM64::W30,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_H0 as u32) => RegisterARM64::H0,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_D0 as u32) => RegisterARM64::D0,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_D1 as u32) => RegisterARM64::D1,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_D2 as u32) => RegisterARM64::D2,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_D3 as u32) => RegisterARM64::D3,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_S0 as u32) => RegisterARM64::S0,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_S1 as u32) => RegisterARM64::S1,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_Q0 as u32)
            || name == format!("reg_{}", Arm64Reg::ARM64_REG_V0 as u32) =>
        {
            RegisterARM64::V0
        }
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_Q1 as u32)
            || name == format!("reg_{}", Arm64Reg::ARM64_REG_V1 as u32) =>
        {
            RegisterARM64::V1
        }
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_Q2 as u32)
            || name == format!("reg_{}", Arm64Reg::ARM64_REG_V2 as u32) =>
        {
            RegisterARM64::V2
        }
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_Q3 as u32)
            || name == format!("reg_{}", Arm64Reg::ARM64_REG_V3 as u32) =>
        {
            RegisterARM64::V3
        }
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_X0 as u32) => RegisterARM64::X0,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_X1 as u32) => RegisterARM64::X1,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_X2 as u32) => RegisterARM64::X2,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_X3 as u32) => RegisterARM64::X3,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_X4 as u32) => RegisterARM64::X4,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_X5 as u32) => RegisterARM64::X5,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_X6 as u32) => RegisterARM64::X6,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_X7 as u32) => RegisterARM64::X7,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_X8 as u32) => RegisterARM64::X8,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_X9 as u32) => RegisterARM64::X9,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_X10 as u32) => RegisterARM64::X10,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_X11 as u32) => RegisterARM64::X11,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_X12 as u32) => RegisterARM64::X12,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_X13 as u32) => RegisterARM64::X13,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_X14 as u32) => RegisterARM64::X14,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_X15 as u32) => RegisterARM64::X15,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_X16 as u32) => RegisterARM64::X16,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_X17 as u32) => RegisterARM64::X17,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_X18 as u32) => RegisterARM64::X18,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_X19 as u32) => RegisterARM64::X19,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_X20 as u32) => RegisterARM64::X20,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_X21 as u32) => RegisterARM64::X21,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_X22 as u32) => RegisterARM64::X22,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_X23 as u32) => RegisterARM64::X23,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_X24 as u32) => RegisterARM64::X24,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_X25 as u32) => RegisterARM64::X25,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_X26 as u32) => RegisterARM64::X26,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_X27 as u32) => RegisterARM64::X27,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_X28 as u32) => RegisterARM64::X28,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_X29 as u32) => RegisterARM64::FP,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_X30 as u32) => RegisterARM64::LR,
        name if name == format!("reg_{}", Arm64Reg::ARM64_REG_SP as u32) => RegisterARM64::SP,
        other => arch_register_to_unicorn(other),
    }
}

fn arch_register_to_unicorn(register: &str) -> RegisterARM64 {
    match register {
        "n" | "z" | "c" | "v" => RegisterARM64::NZCV,
        "tpidr_el0" => RegisterARM64::TPIDR_EL0,
        "fpcr" => RegisterARM64::FPCR,
        "h0" => RegisterARM64::H0,
        "d0" => RegisterARM64::D0,
        "d1" => RegisterARM64::D1,
        "d2" => RegisterARM64::D2,
        "d3" => RegisterARM64::D3,
        "s0" => RegisterARM64::S0,
        "s1" => RegisterARM64::S1,
        "q0" | "v0" => RegisterARM64::V0,
        "q1" | "v1" => RegisterARM64::V1,
        "q2" | "v2" => RegisterARM64::V2,
        "q3" | "v3" => RegisterARM64::V3,
        "w0" => RegisterARM64::W0,
        "w1" => RegisterARM64::W1,
        "w2" => RegisterARM64::W2,
        "w3" => RegisterARM64::W3,
        "w4" => RegisterARM64::W4,
        "w5" => RegisterARM64::W5,
        "w6" => RegisterARM64::W6,
        "w7" => RegisterARM64::W7,
        "w8" => RegisterARM64::W8,
        "w9" => RegisterARM64::W9,
        "w10" => RegisterARM64::W10,
        "w11" => RegisterARM64::W11,
        "w12" => RegisterARM64::W12,
        "w13" => RegisterARM64::W13,
        "w14" => RegisterARM64::W14,
        "w15" => RegisterARM64::W15,
        "w16" => RegisterARM64::W16,
        "w17" => RegisterARM64::W17,
        "w18" => RegisterARM64::W18,
        "w19" => RegisterARM64::W19,
        "w20" => RegisterARM64::W20,
        "w21" => RegisterARM64::W21,
        "w22" => RegisterARM64::W22,
        "w23" => RegisterARM64::W23,
        "w24" => RegisterARM64::W24,
        "w25" => RegisterARM64::W25,
        "w26" => RegisterARM64::W26,
        "w27" => RegisterARM64::W27,
        "w28" => RegisterARM64::W28,
        "w29" => RegisterARM64::W29,
        "w30" => RegisterARM64::W30,
        "x0" => RegisterARM64::X0,
        "x1" => RegisterARM64::X1,
        "x2" => RegisterARM64::X2,
        "x3" => RegisterARM64::X3,
        "x4" => RegisterARM64::X4,
        "x5" => RegisterARM64::X5,
        "x6" => RegisterARM64::X6,
        "x7" => RegisterARM64::X7,
        "x8" => RegisterARM64::X8,
        "x9" => RegisterARM64::X9,
        "x10" => RegisterARM64::X10,
        "x11" => RegisterARM64::X11,
        "x12" => RegisterARM64::X12,
        "x13" => RegisterARM64::X13,
        "x14" => RegisterARM64::X14,
        "x15" => RegisterARM64::X15,
        "x16" => RegisterARM64::X16,
        "x17" => RegisterARM64::X17,
        "x18" => RegisterARM64::X18,
        "x19" => RegisterARM64::X19,
        "x20" => RegisterARM64::X20,
        "x21" => RegisterARM64::X21,
        "x22" => RegisterARM64::X22,
        "x23" => RegisterARM64::X23,
        "x24" => RegisterARM64::X24,
        "x25" => RegisterARM64::X25,
        "x26" => RegisterARM64::X26,
        "x27" => RegisterARM64::X27,
        "x28" => RegisterARM64::X28,
        "x29" => RegisterARM64::FP,
        "x30" => RegisterARM64::LR,
        "sp" => RegisterARM64::SP,
        other => panic!("unsupported arm64 register: {other}"),
    }
}

fn snapshot_arm64_state(
    emu: &Unicorn<'_, ()>,
    tracked_registers: &[String],
    memory: BTreeMap<u64, u8>,
) -> Arm64CpuState {
    let registers = tracked_registers
        .iter()
        .map(|name| {
            let value = match name.as_str() {
                "n" | "z" | "c" | "v" => read_arm64_flag(emu, name) as u128,
                _ => read_arm64_register(emu, name),
            };
            (name.clone(), value)
        })
        .collect();
    let pc = emu.reg_read(RegisterARM64::PC).expect("read pc");
    Arm64CpuState {
        registers,
        pc,
        memory,
    }
}

fn write_arm64_register(emu: &mut Unicorn<'_, ()>, register: &str, value: u128) {
    let unicorn_register = arch_register_to_unicorn(register);
    if is_long_arm64_register(unicorn_register) {
        emu.reg_write_long(unicorn_register, &value.to_le_bytes())
            .unwrap_or_else(|error| panic!("seed {register}: {error:?}"));
    } else {
        emu.reg_write(unicorn_register, value as u64)
            .unwrap_or_else(|error| panic!("seed {register}: {error:?}"));
    }
}

fn read_arm64_register(emu: &Unicorn<'_, ()>, name: &str) -> u128 {
    let unicorn_register = semantic_name_to_unicorn_register(name);
    if is_long_arm64_register(unicorn_register) {
        let bytes = emu
            .reg_read_long(unicorn_register)
            .unwrap_or_else(|error| panic!("read {name}: {error:?}"));
        let mut value = [0u8; 16];
        value[..bytes.len()].copy_from_slice(&bytes);
        u128::from_le_bytes(value)
    } else {
        emu.reg_read(unicorn_register)
            .unwrap_or_else(|error| panic!("read {name}: {error:?}")) as u128
    }
}

fn is_long_arm64_register(register: RegisterARM64) -> bool {
    matches!(
        register,
        RegisterARM64::V0 | RegisterARM64::V1 | RegisterARM64::V2 | RegisterARM64::V3
    )
}

fn build_arm64_program(
    bytes: &[u8],
    fixture: &Arm64Fixture,
    watched_vector_registers: &[String],
) -> Vec<u8> {
    let mut program = Vec::new();
    if fixture
        .registers
        .iter()
        .any(|(register, _)| matches!(*register, "v0" | "q0"))
    {
        program.extend_from_slice(&[0x60, 0x03, 0xc0, 0x3d]);
    }
    if fixture
        .registers
        .iter()
        .any(|(register, _)| matches!(*register, "v1" | "q1"))
    {
        program.extend_from_slice(&[0x61, 0x07, 0xc0, 0x3d]);
    }
    if fixture
        .registers
        .iter()
        .any(|(register, _)| matches!(*register, "v2" | "q2"))
    {
        program.extend_from_slice(&[0x62, 0x0b, 0xc0, 0x3d]);
    }
    if fixture
        .registers
        .iter()
        .any(|(register, _)| matches!(*register, "v3" | "q3"))
    {
        program.extend_from_slice(&[0x63, 0x0f, 0xc0, 0x3d]);
    }
    program.extend_from_slice(bytes);
    if watched_vector_registers
        .iter()
        .any(|name| name == &semantic_name_for_arch_register("v0"))
    {
        program.extend_from_slice(&[0x80, 0x03, 0x80, 0x3d]);
    }
    if watched_vector_registers
        .iter()
        .any(|name| name == &semantic_name_for_arch_register("v1"))
    {
        program.extend_from_slice(&[0x81, 0x07, 0x80, 0x3d]);
    }
    if watched_vector_registers
        .iter()
        .any(|name| name == &semantic_name_for_arch_register("v2"))
    {
        program.extend_from_slice(&[0x82, 0x0b, 0x80, 0x3d]);
    }
    if watched_vector_registers
        .iter()
        .any(|name| name == &semantic_name_for_arch_register("v3"))
    {
        program.extend_from_slice(&[0x83, 0x0f, 0x80, 0x3d]);
    }
    program
}

fn uses_vector_program(fixture: &Arm64Fixture, watched_vector_registers: &[String]) -> bool {
    fixture.registers.iter().any(|(register, _)| {
        matches!(
            *register,
            "v0" | "v1" | "v2" | "v3" | "q0" | "q1" | "q2" | "q3"
        )
    }) || !watched_vector_registers.is_empty()
}

fn seed_vector_fixture_memory(emu: &mut Unicorn<'_, ()>, fixture: &Arm64Fixture) {
    for (register, value) in &fixture.registers {
        let address = match *register {
            "v0" | "q0" => ARM64_VECTOR_INPUT_ADDRESS,
            "v1" | "q1" => ARM64_VECTOR_INPUT_ADDRESS + 16,
            "v2" | "q2" => ARM64_VECTOR_INPUT_ADDRESS + 32,
            "v3" | "q3" => ARM64_VECTOR_INPUT_ADDRESS + 48,
            _ => continue,
        };
        emu.mem_write(address, &value.to_le_bytes())
            .unwrap_or_else(|error| panic!("seed vector memory at 0x{address:x}: {error:?}"));
    }
}

fn watched_vector_memory_ranges(watched_vector_registers: &[String]) -> Vec<(u64, usize)> {
    let mut ranges = Vec::new();
    if watched_vector_registers
        .iter()
        .any(|name| name == &semantic_name_for_arch_register("v0"))
    {
        ranges.push((ARM64_VECTOR_OUTPUT_ADDRESS, 16));
    }
    if watched_vector_registers
        .iter()
        .any(|name| name == &semantic_name_for_arch_register("v1"))
    {
        ranges.push((ARM64_VECTOR_OUTPUT_ADDRESS + 16, 16));
    }
    if watched_vector_registers
        .iter()
        .any(|name| name == &semantic_name_for_arch_register("v2"))
    {
        ranges.push((ARM64_VECTOR_OUTPUT_ADDRESS + 32, 16));
    }
    if watched_vector_registers
        .iter()
        .any(|name| name == &semantic_name_for_arch_register("v3"))
    {
        ranges.push((ARM64_VECTOR_OUTPUT_ADDRESS + 48, 16));
    }
    ranges
}

fn fixture_memory_map(ranges: &[(u64, Vec<u8>)]) -> BTreeMap<u64, u8> {
    let mut memory = BTreeMap::new();
    for (address, bytes) in ranges {
        for (offset, byte) in bytes.iter().copied().enumerate() {
            memory.insert(address + offset as u64, byte);
        }
    }
    memory
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

fn read_arm64_flag(emu: &Unicorn<'_, ()>, flag: &str) -> bool {
    let nzcv = emu.reg_read(RegisterARM64::NZCV).expect("read nzcv");
    let bit = match flag {
        "n" => 31,
        "z" => 30,
        "c" => 29,
        "v" => 28,
        other => panic!("unsupported arm64 flag: {other}"),
    };
    ((nzcv >> bit) & 1) != 0
}

fn write_arm64_flag(emu: &mut Unicorn<'_, ()>, flag: &str, value: bool) {
    let mut nzcv = emu.reg_read(RegisterARM64::NZCV).expect("read nzcv");
    let bit = match flag {
        "n" => 31,
        "z" => 30,
        "c" => 29,
        "v" => 28,
        other => panic!("unsupported arm64 flag: {other}"),
    };
    let mask = 1u64 << bit;
    if value {
        nzcv |= mask;
    } else {
        nzcv &= !mask;
    }
    emu.reg_write(RegisterARM64::NZCV, nzcv)
        .expect("write nzcv");
}

fn map_arm64_data_pages(
    emu: &mut Unicorn<'_, ()>,
    fixture: &Arm64Fixture,
    watched_memory: &[(u64, usize)],
) {
    let mut pages = BTreeSet::new();
    for (address, bytes) in &fixture.memory {
        if !bytes.is_empty() {
            pages.insert(*address & !(ARM64_PAGE_SIZE - 1));
            let end = address + bytes.len() as u64 - 1;
            pages.insert(end & !(ARM64_PAGE_SIZE - 1));
        }
    }
    for (address, size) in watched_memory {
        if *size != 0 {
            pages.insert(*address & !(ARM64_PAGE_SIZE - 1));
            let end = address + *size as u64 - 1;
            pages.insert(end & !(ARM64_PAGE_SIZE - 1));
        }
    }
    for page in pages {
        if page != ARM64_CODE_ADDRESS && page != ARM64_STACK_ADDRESS {
            emu.mem_map(page, ARM64_PAGE_SIZE, Prot::ALL)
                .unwrap_or_else(|error| panic!("map arm64 data page 0x{page:x}: {error:?}"));
        }
    }
}
