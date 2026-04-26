use std::collections::BTreeMap;

use num_bigint::BigUint;
use unicorn_engine::Unicorn;
use unicorn_engine::unicorn_const::{Arch, Mode, Prot};
use unicorn_engine_sys::RegisterX86;

use crate::Architecture;

use super::common::{
    I386_CODE_ADDRESS, I386_CODE_PAGE_SIZE, I386_DATA_ADDRESS, I386_DATA_PAGE_SIZE,
    I386_STACK_ADDRESS, I386_STACK_PAGE_SIZE, I386CpuState, I386CpuStateWide, I386Execution,
    I386ExecutionWide, I386Fixture, I386Register, I386Transition, I386TransitionWide,
    WideI386Fixture, X86Flags,
};
use super::memory::fixture_memory_map;
use super::registers::stable_register_name;

pub(crate) fn unicorn_x86_execution(
    architecture: Architecture,
    bytes: &[u8],
    fixture: I386Fixture,
    watched_memory: &[(u64, usize)],
    start_address: u64,
    end_address: u64,
    instruction_count: usize,
) -> I386Execution {
    let mode = match architecture {
        Architecture::AMD64 => Mode::MODE_64,
        _ => Mode::MODE_32,
    };
    let code_address = unicorn_code_address(start_address);
    let code_map_size = unicorn_code_map_size(code_address, bytes, end_address);
    let mut emu = Unicorn::new(Arch::X86, mode).expect("unicorn x86 instance");
    emu.mem_map(code_address, code_map_size, Prot::ALL)
        .expect("map i386 code page");
    emu.mem_map(I386_STACK_ADDRESS, I386_STACK_PAGE_SIZE, Prot::ALL)
        .expect("map i386 stack page");
    emu.mem_map(I386_DATA_ADDRESS, I386_DATA_PAGE_SIZE, Prot::ALL)
        .expect("map i386 data page");
    write_unicorn_code_bytes(
        &mut emu,
        code_address,
        bytes,
        "write i386 instruction bytes",
    );
    for (register, value) in &fixture.registers {
        seed_unicorn_register(&mut emu, *register, *value);
    }
    for (address, bytes) in &fixture.memory {
        emu.mem_write(*address, bytes)
            .unwrap_or_else(|error| panic!("seed memory at 0x{address:x}: {error:?}"));
    }
    emu.reg_write(RegisterX86::EIP, start_address)
        .expect("seed eip");
    emu.reg_write(RegisterX86::EFLAGS, fixture.eflags as u64)
        .expect("seed eflags");

    let pre = snapshot_i386_state(architecture, &emu, fixture_memory_map(&fixture.memory));
    emu.emu_start(start_address, end_address, 0, instruction_count)
        .expect("execute x86 code");
    let post = snapshot_i386_state(
        architecture,
        &emu,
        read_unicorn_memory(&emu, watched_memory),
    );
    I386Execution {
        transition: I386Transition { pre, post },
        memory_writes: watched_memory.to_vec(),
    }
}

pub(crate) fn snapshot_i386_state(
    architecture: Architecture,
    emu: &Unicorn<'_, ()>,
    memory: BTreeMap<u64, u8>,
) -> I386CpuState {
    let registers = I386Register::all_for_arch(architecture)
        .into_iter()
        .map(|register| {
            (
                stable_register_name(register).to_string(),
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

pub(crate) fn decode_eflags(eflags: u32) -> X86Flags {
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

pub(crate) fn seed_unicorn_register(
    emu: &mut Unicorn<'_, ()>,
    register: I386Register,
    value: u128,
) {
    match register.bit_width() {
        128 => emu
            .reg_write_long(register.unicorn_register(), &value.to_le_bytes())
            .unwrap_or_else(|error| panic!("seed {register:?}: {error:?}")),
        _ => emu
            .reg_write(register.unicorn_register(), value as u64)
            .unwrap_or_else(|error| panic!("seed {register:?}: {error:?}")),
    }
}

pub(crate) fn read_unicorn_register(emu: &Unicorn<'_, ()>, register: I386Register) -> u128 {
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

pub(crate) fn unicorn_amd64_single_instruction_wide(
    bytes: &[u8],
    fixture: &WideI386Fixture,
    tracked_registers: &[I386Register],
) -> I386ExecutionWide {
    let code_map_size = unicorn_code_map_size(
        I386_CODE_ADDRESS,
        bytes,
        I386_CODE_ADDRESS + bytes.len() as u64,
    );
    let mut emu = Unicorn::new(Arch::X86, Mode::MODE_64).expect("unicorn x86 instance");
    emu.mem_map(I386_CODE_ADDRESS, code_map_size, Prot::ALL)
        .expect("map code page");
    emu.mem_map(I386_STACK_ADDRESS, I386_STACK_PAGE_SIZE, Prot::ALL)
        .expect("map stack page");
    emu.mem_map(I386_DATA_ADDRESS, I386_DATA_PAGE_SIZE, Prot::ALL)
        .expect("map data page");
    write_unicorn_code_bytes(
        &mut emu,
        I386_CODE_ADDRESS,
        bytes,
        "write instruction bytes",
    );
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

    let pre = snapshot_x86_state_wide(
        &emu,
        tracked_registers,
        fixture_memory_map(&fixture.base.memory),
    );
    emu.emu_start(
        I386_CODE_ADDRESS,
        I386_CODE_ADDRESS + bytes.len() as u64,
        0,
        0,
    )
    .expect("execute one instruction");
    let post = snapshot_x86_state_wide(&emu, tracked_registers, BTreeMap::new());
    I386ExecutionWide {
        transition: I386TransitionWide { pre, post },
    }
}

pub(crate) fn write_unicorn_code_bytes(
    emu: &mut Unicorn<'_, ()>,
    address: u64,
    bytes: &[u8],
    context: &str,
) {
    if emu.mem_write(address, bytes).is_ok() {
        return;
    }
    for (offset, byte) in bytes.iter().enumerate() {
        emu.mem_write(address + offset as u64, &[*byte])
            .unwrap_or_else(|error| {
                panic!("{context} at +0x{offset:x}: {error:?}");
            });
    }
}

pub(crate) fn unicorn_code_address(start_address: u64) -> u64 {
    let page = I386_CODE_PAGE_SIZE;
    start_address & !(page - 1)
}

pub(crate) fn unicorn_code_map_size(code_address: u64, bytes: &[u8], end_address: u64) -> u64 {
    let minimum = I386_CODE_PAGE_SIZE as usize;
    let span = end_address.saturating_sub(code_address) as usize;
    let needed = bytes.len().max(span).max(minimum);
    let page = I386_CODE_PAGE_SIZE as usize;
    needed.next_multiple_of(page) as u64
}

pub(crate) fn snapshot_x86_state_wide(
    emu: &Unicorn<'_, ()>,
    tracked_registers: &[I386Register],
    memory: BTreeMap<u64, u8>,
) -> I386CpuStateWide {
    let registers = tracked_registers
        .iter()
        .map(|register| {
            (
                stable_register_name(*register).to_string(),
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

pub(crate) fn read_unicorn_register_wide(emu: &Unicorn<'_, ()>, register: I386Register) -> BigUint {
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

pub(crate) fn read_unicorn_memory(
    emu: &Unicorn<'_, ()>,
    ranges: &[(u64, usize)],
) -> BTreeMap<u64, u8> {
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
