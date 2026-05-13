use crate::ir::lir::{LirAddressSpace, LirFenceKind, LirLocation, LirTrapKind};
use inkwell::builder::Builder;
use inkwell::types::IntType;
use inkwell::values::IntValue;
use std::io::Error;

pub(super) fn const_int(ty: IntType<'_>, value: u128) -> IntValue<'_> {
    let words = [value as u64, (value >> 64) as u64];
    ty.const_int_arbitrary_precision(&words)
}

pub(super) fn coerce_int_value_width<'ctx>(
    builder: &Builder<'ctx>,
    value: IntValue<'ctx>,
    target: IntType<'ctx>,
    zext_name: &str,
    trunc_name: &str,
) -> Result<IntValue<'ctx>, Error> {
    let current = value.get_type().get_bit_width();
    let wanted = target.get_bit_width();
    if current == wanted {
        Ok(value)
    } else if current < wanted {
        builder
            .build_int_z_extend(value, target, zext_name)
            .map_err(|err| Error::other(err.to_string()))
    } else {
        builder
            .build_int_truncate(value, target, trunc_name)
            .map_err(|err| Error::other(err.to_string()))
    }
}

pub(super) fn sanitize_symbol(name: &str) -> String {
    name.chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '_' => ch,
            _ => '_',
        })
        .collect()
}

pub(super) fn push_unique_location(locations: &mut Vec<LirLocation>, location: LirLocation) {
    if !locations.iter().any(|existing| existing == &location) {
        locations.push(location);
    }
}

pub(super) fn render_location(location: &LirLocation) -> String {
    match location {
        LirLocation::Register { name, bits } => format!("reg_{}_{}", name, bits),
        LirLocation::Flag { name, bits } => format!("flag_{}_{}", name, bits),
        LirLocation::ProgramCounter { bits } => format!("pc_{}", bits),
        LirLocation::Temporary { id, bits } => format!("tmp_{}_{}", id, bits),
        LirLocation::Memory { space, bits, .. } => {
            format!("mem_{}_{}", render_address_space(space), bits)
        }
        LirLocation::IndexedMemory { name, bits, .. } => {
            format!("idxmem_{}_{}", sanitize_symbol(name), bits)
        }
        LirLocation::StackMemory { name, offset, bits } => {
            format!("stackmem_{}_{}_{}", sanitize_symbol(name), offset, bits)
        }
    }
}

pub(super) fn render_address_space(space: &LirAddressSpace) -> String {
    match space {
        LirAddressSpace::Default => "default".to_string(),
        LirAddressSpace::State => "state".to_string(),
        LirAddressSpace::Stack => "stack".to_string(),
        LirAddressSpace::Heap => "heap".to_string(),
        LirAddressSpace::Global => "global".to_string(),
        LirAddressSpace::Io => "io".to_string(),
        LirAddressSpace::CpuMemory { name } => format!("cpu_{}", sanitize_symbol(name)),
        LirAddressSpace::Segment { name } => format!("segment_{}", sanitize_symbol(name)),
        LirAddressSpace::Named { name } => {
            format!("named_{}", sanitize_symbol(name))
        }
    }
}

pub(super) fn render_fence_kind(kind: &LirFenceKind) -> String {
    match kind {
        LirFenceKind::Acquire => "acquire".to_string(),
        LirFenceKind::Release => "release".to_string(),
        LirFenceKind::AcquireRelease => "acquire_release".to_string(),
        LirFenceKind::SequentiallyConsistent => "seq_cst".to_string(),
        LirFenceKind::Named { name } => format!("named_{}", sanitize_symbol(name)),
    }
}

pub(super) fn render_trap_kind(kind: &LirTrapKind) -> String {
    match kind {
        LirTrapKind::Breakpoint => "breakpoint".to_string(),
        LirTrapKind::DivideError => "divide_error".to_string(),
        LirTrapKind::Overflow => "overflow".to_string(),
        LirTrapKind::InvalidOpcode => "invalid_opcode".to_string(),
        LirTrapKind::GeneralProtection => "general_protection".to_string(),
        LirTrapKind::PageFault => "page_fault".to_string(),
        LirTrapKind::AlignmentFault => "alignment_fault".to_string(),
        LirTrapKind::Syscall => "syscall".to_string(),
        LirTrapKind::Interrupt => "interrupt".to_string(),
        LirTrapKind::Named { name } => format!("named_{}", sanitize_symbol(name)),
    }
}
