use crate::irs::mir::{Mir, MirAddressSpace, MirOperationKind, MirValue};
use std::collections::HashMap;

type DefMap = HashMap<String, MirOperationKind>;

pub fn optimize_abi(mir: &mut Mir) {
    let defs = build_defs(mir);
    for block in mir.blocks_mut() {
        for operation in &mut block.operations {
            match &mut operation.kind {
                MirOperationKind::Load {
                    address_space,
                    address,
                    ..
                }
                | MirOperationKind::Store {
                    address_space,
                    address,
                    ..
                } => {
                    if matches!(address_space, MirAddressSpace::Default)
                        && is_stack_derived(address, &defs)
                    {
                        *address_space = MirAddressSpace::Stack;
                    }
                }
                _ => {}
            }
        }
    }
}

fn build_defs(mir: &Mir) -> DefMap {
    mir.blocks()
        .iter()
        .flat_map(|block| block.operations.iter())
        .filter_map(|operation| {
            operation
                .result
                .as_ref()
                .map(|result| (result.clone(), operation.kind.clone()))
        })
        .collect()
}

fn is_stack_derived(value: &MirValue, defs: &DefMap) -> bool {
    is_stack_derived_with_depth(value, defs, 0)
}

fn is_stack_derived_with_depth(value: &MirValue, defs: &DefMap, depth: usize) -> bool {
    if depth > 16 {
        return false;
    }

    match value {
        MirValue::Named { name, .. } if is_stack_pointer_name(name) => true,
        MirValue::Named { name, .. } => match defs.get(name) {
            Some(MirOperationKind::Add { lhs, rhs, .. })
            | Some(MirOperationKind::Sub { lhs, rhs, .. }) => {
                let lhs_stack = is_stack_derived_with_depth(lhs, defs, depth + 1);
                let rhs_stack = is_stack_derived_with_depth(rhs, defs, depth + 1);
                (lhs_stack && is_constant(rhs)) || (rhs_stack && is_constant(lhs))
            }
            Some(MirOperationKind::Copy { value, .. }) => {
                is_stack_derived_with_depth(value, defs, depth + 1)
            }
            _ => false,
        },
        _ => false,
    }
}

fn is_stack_pointer_name(name: &str) -> bool {
    matches!(name, "sp" | "fp")
}

fn is_constant(value: &MirValue) -> bool {
    matches!(value, MirValue::Integer { .. })
}
