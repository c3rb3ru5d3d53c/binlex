use crate::semantics::{
    SemanticAddressSpace, SemanticFenceKind, SemanticLocation, SemanticTrapKind,
};
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

pub(super) fn push_unique_location(
    locations: &mut Vec<SemanticLocation>,
    location: SemanticLocation,
) {
    if !locations.iter().any(|existing| existing == &location) {
        locations.push(location);
    }
}

pub(super) fn render_location(location: &SemanticLocation) -> String {
    match location {
        SemanticLocation::Register { name, bits } => format!("reg_{}_{}", name, bits),
        SemanticLocation::Flag { name, bits } => format!("flag_{}_{}", name, bits),
        SemanticLocation::ProgramCounter { bits } => format!("pc_{}", bits),
        SemanticLocation::Temporary { id, bits } => format!("tmp_{}_{}", id, bits),
        SemanticLocation::Memory { space, bits, .. } => {
            format!("mem_{}_{}", render_address_space(space), bits)
        }
        SemanticLocation::IndexedMemory { name, bits, .. } => {
            format!("idxmem_{}_{}", sanitize_symbol(name), bits)
        }
        SemanticLocation::StackMemory { name, offset, bits } => {
            format!("stackmem_{}_{}_{}", sanitize_symbol(name), offset, bits)
        }
    }
}

pub(super) fn render_address_space(space: &SemanticAddressSpace) -> String {
    match space {
        SemanticAddressSpace::Default => "default".to_string(),
        SemanticAddressSpace::State => "state".to_string(),
        SemanticAddressSpace::Stack => "stack".to_string(),
        SemanticAddressSpace::Heap => "heap".to_string(),
        SemanticAddressSpace::Global => "global".to_string(),
        SemanticAddressSpace::Io => "io".to_string(),
        SemanticAddressSpace::CpuMemory { name } => format!("cpu_{}", sanitize_symbol(name)),
        SemanticAddressSpace::Segment { name } => format!("segment_{}", sanitize_symbol(name)),
        SemanticAddressSpace::Named { name } => {
            format!("named_{}", sanitize_symbol(name))
        }
    }
}

pub(super) fn render_fence_kind(kind: &SemanticFenceKind) -> String {
    match kind {
        SemanticFenceKind::Acquire => "acquire".to_string(),
        SemanticFenceKind::Release => "release".to_string(),
        SemanticFenceKind::AcquireRelease => "acquire_release".to_string(),
        SemanticFenceKind::SequentiallyConsistent => "seq_cst".to_string(),
        SemanticFenceKind::Named { name } => format!("named_{}", sanitize_symbol(name)),
    }
}

pub(super) fn render_trap_kind(kind: &SemanticTrapKind) -> String {
    match kind {
        SemanticTrapKind::Breakpoint => "breakpoint".to_string(),
        SemanticTrapKind::DivideError => "divide_error".to_string(),
        SemanticTrapKind::Overflow => "overflow".to_string(),
        SemanticTrapKind::InvalidOpcode => "invalid_opcode".to_string(),
        SemanticTrapKind::GeneralProtection => "general_protection".to_string(),
        SemanticTrapKind::PageFault => "page_fault".to_string(),
        SemanticTrapKind::AlignmentFault => "alignment_fault".to_string(),
        SemanticTrapKind::Syscall => "syscall".to_string(),
        SemanticTrapKind::Interrupt => "interrupt".to_string(),
        SemanticTrapKind::Named { name } => format!("named_{}", sanitize_symbol(name)),
    }
}
