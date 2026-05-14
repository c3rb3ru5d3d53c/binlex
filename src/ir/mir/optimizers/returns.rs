use crate::ir::mir::analysis::block_register_aliases;
use crate::ir::mir::{Mir, MirAddressSpace, MirOperationKind, MirTerminator, MirType, MirValue};
use std::collections::HashMap;

type DefMap = HashMap<String, MirOperationKind>;

pub fn optimize_returns(mir: &mut Mir) {
    let aliases = block_register_aliases(mir);
    let defs = build_defs(mir);
    let abi_return = abi_return_register(&defs);

    for block in mir.blocks_mut() {
        let Some(MirTerminator::Return { values }) = block.terminator.as_mut() else {
            continue;
        };
        if values.len() != 1 {
            continue;
        }
        if !is_machine_return_target(&values[0], &defs) {
            continue;
        }

        let Some(return_value) = abi_return.clone().or_else(|| {
            aliases
                .get(&block.name)
                .and_then(abi_return_value_from_aliases)
        }) else {
            continue;
        };
        values[0] = return_value;
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

fn is_machine_return_target(value: &MirValue, defs: &DefMap) -> bool {
    is_machine_return_target_with_depth(value, defs, 0)
}

fn is_machine_return_target_with_depth(value: &MirValue, defs: &DefMap, depth: usize) -> bool {
    if depth > 16 {
        return false;
    }

    match value {
        MirValue::Named { name, .. } => match defs.get(name) {
            Some(MirOperationKind::Load {
                address_space,
                address,
                ..
            }) => {
                matches!(
                    address_space,
                    MirAddressSpace::Default | MirAddressSpace::Stack
                ) && is_stack_derived(address, defs)
            }
            Some(MirOperationKind::Intrinsic {
                name, arguments, ..
            }) if name == "lir.set" && arguments.len() == 1 => {
                is_machine_return_target_with_depth(&arguments[0], defs, depth + 1)
            }
            _ => false,
        },
        _ => false,
    }
}

fn abi_return_register(defs: &DefMap) -> Option<MirValue> {
    for (register, bits) in [("rax", 64), ("eax", 32), ("x0", 64), ("w0", 32)] {
        if defs.contains_key(register) {
            return Some(MirValue::named(
                register.to_string(),
                MirType::integer(bits),
            ));
        }
    }
    None
}

fn abi_return_value_from_aliases(aliases: &HashMap<String, MirValue>) -> Option<MirValue> {
    for register in ["rax", "eax", "x0", "w0"] {
        if let Some(value) = aliases.get(register) {
            return Some(value.clone());
        }
    }
    None
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
            Some(MirOperationKind::Intrinsic {
                name, arguments, ..
            }) if name == "lir.set" && arguments.len() == 1 => {
                is_stack_derived_with_depth(&arguments[0], defs, depth + 1)
            }
            _ => false,
        },
        _ => false,
    }
}

fn is_stack_pointer_name(name: &str) -> bool {
    matches!(
        name,
        "rsp" | "esp" | "sp" | "rbp" | "ebp" | "bp" | "fp" | "sp_el0" | "sp_el1"
    )
}

fn is_constant(value: &MirValue) -> bool {
    matches!(value, MirValue::Integer { .. })
}
