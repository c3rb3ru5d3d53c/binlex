use crate::semantics::{
    SemanticAddressSpace, SemanticFenceKind, SemanticLocation, SemanticTrapKind,
};
use inkwell::types::IntType;
use inkwell::values::IntValue;

pub(super) fn const_int(ty: IntType<'_>, value: u128) -> IntValue<'_> {
    let words = [value as u64, (value >> 64) as u64];
    ty.const_int_arbitrary_precision(&words)
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
        SemanticAddressSpace::ArchSpecific { name } => {
            format!("arch_{}", sanitize_symbol(name))
        }
    }
}

pub(super) fn render_fence_kind(kind: &SemanticFenceKind) -> String {
    match kind {
        SemanticFenceKind::Acquire => "acquire".to_string(),
        SemanticFenceKind::Release => "release".to_string(),
        SemanticFenceKind::AcquireRelease => "acquire_release".to_string(),
        SemanticFenceKind::SequentiallyConsistent => "seq_cst".to_string(),
        SemanticFenceKind::ArchSpecific { name } => format!("arch_{}", sanitize_symbol(name)),
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
        SemanticTrapKind::ArchSpecific { name } => format!("arch_{}", sanitize_symbol(name)),
    }
}
