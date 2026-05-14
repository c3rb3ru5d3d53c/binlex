use crate::ir::mir::{
    Mir, MirAddressSpace, MirOperation, MirOperationKind, MirTerminator, MirType, MirValue,
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

fn rewrite_operation(operation: &mut MirOperation, aliases: &AliasMap) {
    match &mut operation.kind {
        MirOperationKind::Add { lhs, rhs, .. }
        | MirOperationKind::Sub { lhs, rhs, .. }
        | MirOperationKind::Mul { lhs, rhs, .. }
        | MirOperationKind::And { lhs, rhs, .. }
        | MirOperationKind::Or { lhs, rhs, .. }
        | MirOperationKind::Xor { lhs, rhs, .. }
        | MirOperationKind::Shl { lhs, rhs, .. }
        | MirOperationKind::LShr { lhs, rhs, .. }
        | MirOperationKind::AShr { lhs, rhs, .. }
        | MirOperationKind::Icmp { lhs, rhs, .. } => {
            rewrite_value(lhs, aliases);
            rewrite_value(rhs, aliases);
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
        MirOperationKind::Extract { value, .. }
        | MirOperationKind::Not { value, .. }
        | MirOperationKind::Popcount { value, .. } => rewrite_value(value, aliases),
        MirOperationKind::Load { address, .. } => {
            rewrite_value(address, aliases);
        }
        MirOperationKind::Store { address, value, .. } => {
            rewrite_value(address, aliases);
            rewrite_value(value, aliases);
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
