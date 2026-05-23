use crate::ir::mir::analysis::block_register_aliases;
use crate::ir::mir::{Mir, MirAddressSpace, MirOperationKind, MirTerminator, MirType, MirValue};
use std::collections::HashMap;

#[derive(Clone, Debug)]
enum ReturnDef {
    Load {
        address_space: MirAddressSpace,
        address: MirValue,
    },
    Add {
        lhs: MirValue,
        rhs: MirValue,
    },
    Sub {
        lhs: MirValue,
        rhs: MirValue,
    },
    Set {
        value: MirValue,
    },
}

type DefMap = HashMap<String, ReturnDef>;

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
    let mut defs = DefMap::new();

    for block in mir.blocks() {
        for operation in &block.operations {
            let Some(result) = operation.result.as_ref() else {
                continue;
            };
            let def = match &operation.kind {
                MirOperationKind::Load {
                    address_space,
                    address,
                    ..
                } => ReturnDef::Load {
                    address_space: address_space.clone(),
                    address: address.clone(),
                },
                MirOperationKind::Add { lhs, rhs, .. } => ReturnDef::Add {
                    lhs: lhs.clone(),
                    rhs: rhs.clone(),
                },
                MirOperationKind::Sub { lhs, rhs, .. } => ReturnDef::Sub {
                    lhs: lhs.clone(),
                    rhs: rhs.clone(),
                },
                MirOperationKind::Copy { value, .. } => ReturnDef::Set {
                    value: value.clone(),
                },
                _ => continue,
            };
            defs.insert(result.clone(), def);
        }
    }

    defs
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
            Some(ReturnDef::Load {
                address_space,
                address,
            }) => {
                matches!(
                    address_space,
                    MirAddressSpace::Default | MirAddressSpace::Stack
                ) && is_stack_derived(address, defs)
            }
            Some(ReturnDef::Set { value }) => {
                is_machine_return_target_with_depth(value, defs, depth + 1)
            }
            _ => false,
        },
        _ => false,
    }
}

fn abi_return_register(defs: &DefMap) -> Option<MirValue> {
    for (register, bits) in [
        ("ret0", 64),
        ("eax", 32),
        ("rax", 64),
        ("w0", 32),
        ("x0", 64),
    ] {
        if let Some(def) = defs.get(register) {
            return Some(MirValue::named(
                register.to_string(),
                return_def_type(def).unwrap_or_else(|| MirType::integer(bits)),
            ));
        }
    }
    None
}

fn abi_return_value_from_aliases(aliases: &HashMap<String, MirValue>) -> Option<MirValue> {
    for register in ["ret0", "eax", "rax", "w0", "x0"] {
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
            Some(ReturnDef::Add { lhs, rhs }) | Some(ReturnDef::Sub { lhs, rhs }) => {
                let lhs_stack = is_stack_derived_with_depth(lhs, defs, depth + 1);
                let rhs_stack = is_stack_derived_with_depth(rhs, defs, depth + 1);
                (lhs_stack && is_constant(rhs)) || (rhs_stack && is_constant(lhs))
            }
            Some(ReturnDef::Set { value }) => is_stack_derived_with_depth(value, defs, depth + 1),
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

fn return_def_type(def: &ReturnDef) -> Option<MirType> {
    match def {
        ReturnDef::Set { value } => value_type(value),
        _ => None,
    }
}

fn value_type(value: &MirValue) -> Option<MirType> {
    match value {
        MirValue::Named { ty, .. } | MirValue::Null { ty } | MirValue::Undef { ty } => {
            Some(ty.clone())
        }
        MirValue::Integer { bits, .. } => Some(MirType::integer(*bits)),
        MirValue::Boolean(_) => Some(MirType::integer(1)),
    }
}
