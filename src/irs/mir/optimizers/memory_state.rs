use crate::irs::mir::{
    Mir, MirAddressSpace, MirCastOperation, MirOperation, MirOperationKind, MirTerminator, MirType,
    MirValue,
};
use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct MemoryCell {
    address_space: MirAddressSpace,
    address: MirValue,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MemoryEntry {
    value: MirValue,
    ty: MirType,
}

type AliasMap = HashMap<String, MirValue>;
type MemoryMap = HashMap<MemoryCell, MemoryEntry>;

enum WidenedValue {
    Alias(MirValue),
    Operation(MirOperation),
}

pub fn optimize_memory_state(mir: &mut Mir) {
    for block in mir.blocks_mut() {
        let mut aliases = AliasMap::new();
        let mut memory = MemoryMap::new();
        let mut normalized = Vec::with_capacity(block.operations.len());

        for mut operation in std::mem::take(&mut block.operations) {
            rewrite_operation(&mut operation, &aliases);

            match &operation.kind {
                MirOperationKind::Load {
                    address_space,
                    address,
                    ty,
                } => {
                    let Some(result) = operation.result.clone() else {
                        normalized.push(operation);
                        continue;
                    };
                    let cell = canonicalize_cell(
                        MemoryCell {
                            address_space: address_space.clone(),
                            address: address.clone(),
                        },
                        &aliases,
                    );
                    if let Some(entry) = memory.get(&cell) {
                        if &entry.ty == ty {
                            aliases.insert(result, entry.value.clone());
                            continue;
                        }
                        if let Some(alias) =
                            widened_stack_slot_value(&result, &cell.address_space, entry, ty)
                        {
                            match alias {
                                WidenedValue::Alias(value) => {
                                    aliases.insert(result, value);
                                }
                                WidenedValue::Operation(operation) => {
                                    normalized.push(operation);
                                }
                            }
                            continue;
                        }
                    }
                    aliases.remove(&result);
                    normalized.push(operation);
                }
                MirOperationKind::Store {
                    address_space,
                    address,
                    value,
                    ty,
                } => {
                    let cell = canonicalize_cell(
                        MemoryCell {
                            address_space: address_space.clone(),
                            address: address.clone(),
                        },
                        &aliases,
                    );

                    if memory.get(&cell)
                        == Some(&MemoryEntry {
                            value: value.clone(),
                            ty: ty.clone(),
                        })
                    {
                        continue;
                    }

                    invalidate_memory_aliases(&mut memory, &cell);
                    memory.insert(
                        cell,
                        MemoryEntry {
                            value: value.clone(),
                            ty: ty.clone(),
                        },
                    );
                    normalized.push(operation);
                }
                MirOperationKind::MemoryCopy {
                    src_space,
                    dst_space,
                    ..
                } => {
                    aliases.clear();
                    memory.retain(|cell, _| {
                        cell.address_space != *src_space && cell.address_space != *dst_space
                    });
                    normalized.push(operation);
                }
                MirOperationKind::Call { memory_effects, .. } => {
                    aliases.clear();
                    if memory_effects.is_empty() {
                        memory.clear();
                    } else {
                        invalidate_memory_regions(&mut memory, memory_effects);
                    }
                    if let Some(result) = operation.result.as_ref() {
                        aliases.remove(result);
                    }
                    normalized.push(operation);
                }
                MirOperationKind::Intrinsic { name, .. } if name == "lir.fence.acquire" => {}
                MirOperationKind::Intrinsic { .. } => {
                    aliases.clear();
                    memory.clear();
                    if let Some(result) = operation.result.as_ref() {
                        aliases.remove(result);
                    }
                    normalized.push(operation);
                }
                _ => {
                    if let Some(result) = operation.result.as_ref() {
                        aliases.remove(result);
                    }
                    normalized.push(operation);
                }
            }
        }

        if let Some(terminator) = block.terminator.as_mut() {
            rewrite_terminator(terminator, &aliases);
        }

        block.operations = normalized;
    }
}

fn invalidate_memory_aliases(memory: &mut MemoryMap, cell: &MemoryCell) {
    memory.retain(|existing, _| {
        !(existing.address_space == cell.address_space && existing.address == cell.address)
    });
}

fn invalidate_memory_regions(memory: &mut MemoryMap, effects: &[MirAddressSpace]) {
    memory.retain(|existing, _| {
        !effects
            .iter()
            .any(|effect| address_space_matches_effect(&existing.address_space, effect))
    });
}

fn address_space_matches_effect(space: &MirAddressSpace, effect: &MirAddressSpace) -> bool {
    if space == effect {
        return true;
    }

    matches!(
        (space, effect),
        (
            MirAddressSpace::Stack
                | MirAddressSpace::Local { .. }
                | MirAddressSpace::Argument { .. }
                | MirAddressSpace::Spill { .. }
                | MirAddressSpace::Incoming { .. }
                | MirAddressSpace::SavedFrame { .. }
                | MirAddressSpace::ReturnAddress { .. },
            MirAddressSpace::Stack
        ) | (
            MirAddressSpace::Incoming { .. } | MirAddressSpace::Argument { .. },
            MirAddressSpace::Incoming { .. }
        ) | (MirAddressSpace::HeapObject { .. }, MirAddressSpace::Heap)
            | (
                MirAddressSpace::GlobalObject { .. },
                MirAddressSpace::Global
            )
    )
}

fn widened_stack_slot_value(
    result: &str,
    address_space: &MirAddressSpace,
    entry: &MemoryEntry,
    load_ty: &MirType,
) -> Option<WidenedValue> {
    if !is_stack_slot_space(address_space) {
        return None;
    }

    let store_bits = integer_bits(&entry.ty)?;
    let load_bits = integer_bits(load_ty)?;
    if store_bits > load_bits {
        return None;
    }

    match &entry.value {
        MirValue::Integer { value, .. } => Some(WidenedValue::Alias(MirValue::integer(
            mask_integer(*value, store_bits),
            load_bits,
        ))),
        MirValue::Boolean(value) if load_bits >= 1 => Some(WidenedValue::Alias(MirValue::integer(
            i128::from(*value),
            load_bits,
        ))),
        value if store_bits == load_bits => Some(WidenedValue::Alias(value.clone())),
        value => Some(WidenedValue::Operation(MirOperation::new(
            Some(result.to_string()),
            MirOperationKind::Cast {
                op: MirCastOperation::ZeroExtend,
                value: value.clone(),
                ty: load_ty.clone(),
            },
        ))),
    }
}

fn is_stack_slot_space(space: &MirAddressSpace) -> bool {
    matches!(
        space,
        MirAddressSpace::Local { .. }
            | MirAddressSpace::Argument { .. }
            | MirAddressSpace::Spill { .. }
            | MirAddressSpace::Incoming { .. }
            | MirAddressSpace::SavedFrame { .. }
    )
}

fn integer_bits(ty: &MirType) -> Option<u16> {
    match ty {
        MirType::Integer(bits) => Some(*bits),
        _ => None,
    }
}

fn mask_integer(value: i128, bits: u16) -> i128 {
    if bits >= 128 {
        value
    } else {
        value & ((1i128 << bits) - 1)
    }
}

fn rewrite_operation(operation: &mut MirOperation, aliases: &AliasMap) {
    match &mut operation.kind {
        MirOperationKind::Add { lhs, rhs, .. }
        | MirOperationKind::Sub { lhs, rhs, .. }
        | MirOperationKind::Mul { lhs, rhs, .. }
        | MirOperationKind::FAdd { lhs, rhs, .. }
        | MirOperationKind::FSub { lhs, rhs, .. }
        | MirOperationKind::FMul { lhs, rhs, .. }
        | MirOperationKind::FDiv { lhs, rhs, .. }
        | MirOperationKind::And { lhs, rhs, .. }
        | MirOperationKind::Or { lhs, rhs, .. }
        | MirOperationKind::Xor { lhs, rhs, .. }
        | MirOperationKind::Shl { lhs, rhs, .. }
        | MirOperationKind::LShr { lhs, rhs, .. }
        | MirOperationKind::AShr { lhs, rhs, .. }
        | MirOperationKind::UDiv { lhs, rhs, .. }
        | MirOperationKind::SDiv { lhs, rhs, .. }
        | MirOperationKind::URem { lhs, rhs, .. }
        | MirOperationKind::SRem { lhs, rhs, .. }
        | MirOperationKind::RotateLeft { lhs, rhs, .. }
        | MirOperationKind::RotateRight { lhs, rhs, .. }
        | MirOperationKind::Icmp { lhs, rhs, .. }
        | MirOperationKind::Fcmp { lhs, rhs, .. } => {
            rewrite_value(lhs, aliases);
            rewrite_value(rhs, aliases);
        }
        MirOperationKind::Concat { parts, .. } => {
            for part in parts {
                rewrite_value(part, aliases);
            }
        }
        MirOperationKind::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            rewrite_value(condition, aliases);
            rewrite_value(when_true, aliases);
            rewrite_value(when_false, aliases);
        }
        MirOperationKind::Copy { value, .. }
        | MirOperationKind::Extract { value, .. }
        | MirOperationKind::Neg { value, .. }
        | MirOperationKind::Not { value, .. }
        | MirOperationKind::Popcount { value, .. }
        | MirOperationKind::CountLeadingZeros { value, .. }
        | MirOperationKind::CountTrailingZeros { value, .. } => rewrite_value(value, aliases),
        MirOperationKind::Load { address, .. } | MirOperationKind::AddressOf { address, .. } => {
            rewrite_value(address, aliases);
        }
        MirOperationKind::Store { address, value, .. } => {
            rewrite_value(address, aliases);
            rewrite_value(value, aliases);
        }
        MirOperationKind::MemoryCopy {
            src_address,
            dst_address,
            count,
            decrement,
            ..
        } => {
            rewrite_value(src_address, aliases);
            rewrite_value(dst_address, aliases);
            rewrite_value(count, aliases);
            rewrite_value(decrement, aliases);
        }
        MirOperationKind::Cast { value, .. } => {
            rewrite_value(value, aliases);
        }
        MirOperationKind::Call { arguments, .. }
        | MirOperationKind::Intrinsic { arguments, .. } => {
            for argument in arguments {
                rewrite_value(argument, aliases);
            }
        }
    }
}

fn rewrite_terminator(terminator: &mut MirTerminator, aliases: &AliasMap) {
    match terminator {
        MirTerminator::Jump { arguments, .. } => {
            for argument in arguments {
                rewrite_value(argument, aliases);
            }
        }
        MirTerminator::CondBr {
            condition,
            then_arguments,
            else_arguments,
            ..
        } => {
            rewrite_value(condition, aliases);
            for argument in then_arguments {
                rewrite_value(argument, aliases);
            }
            for argument in else_arguments {
                rewrite_value(argument, aliases);
            }
        }
        MirTerminator::Return { values } => {
            for value in values {
                rewrite_value(value, aliases);
            }
        }
        MirTerminator::Trap | MirTerminator::Unreachable => {}
    }
}

fn rewrite_value(value: &mut MirValue, aliases: &AliasMap) {
    if let MirValue::Named { name, .. } = value {
        if let Some(replacement) = aliases.get(name) {
            *value = replacement.clone();
        }
    }
}

fn canonicalize_cell(mut cell: MemoryCell, aliases: &AliasMap) -> MemoryCell {
    rewrite_value(&mut cell.address, aliases);
    cell
}
