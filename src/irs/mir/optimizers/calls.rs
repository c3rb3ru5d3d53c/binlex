use crate::irs::mir::analysis::build_use_counts;
use crate::irs::mir::{
    Mir, MirAddressSpace, MirCastOperation, MirControlTarget, MirOperation, MirOperationKind,
    MirValue,
};
use std::collections::HashMap;

#[derive(Clone, Debug)]
enum CallDef {
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
    Cast {
        op: MirCastOperation,
        value: MirValue,
    },
}

pub fn optimize_calls(mir: &mut Mir) {
    let uses = build_use_counts(mir);
    let defs = build_defs(mir);

    for block in mir.blocks_mut() {
        let mut normalized = Vec::with_capacity(block.operations.len());
        let mut no_return_call = false;

        for operation in std::mem::take(&mut block.operations) {
            if matches!(operation.kind, MirOperationKind::Call { .. })
                && normalized
                    .last()
                    .is_some_and(|previous| is_call_return_address_store(previous, &defs))
            {
                normalized.pop();
            }

            let mut operation = operation;
            if matches!(
                &operation.kind,
                MirOperationKind::Call { target, .. } if is_no_return_target(target)
            ) {
                no_return_call = true;
            }
            let Some(result) = operation.result.as_ref() else {
                normalized.push(operation);
                if no_return_call {
                    break;
                }
                continue;
            };
            if uses.contains_key(result) || !matches!(operation.kind, MirOperationKind::Call { .. })
            {
                normalized.push(operation);
                if no_return_call {
                    break;
                }
                continue;
            }

            if matches!(operation.kind, MirOperationKind::Call { .. }) {
                operation.result = None;
            }
            normalized.push(operation);
            if no_return_call {
                break;
            }
        }

        block.operations = normalized;
        if no_return_call {
            block.terminator = Some(crate::irs::mir::MirTerminator::Unreachable);
        }
    }
}

fn build_defs(mir: &Mir) -> HashMap<String, CallDef> {
    let mut defs = HashMap::new();

    for block in mir.blocks() {
        for operation in &block.operations {
            let Some(result) = operation.result.as_ref() else {
                continue;
            };
            let def = match &operation.kind {
                MirOperationKind::Add { lhs, rhs, .. } => CallDef::Add {
                    lhs: lhs.clone(),
                    rhs: rhs.clone(),
                },
                MirOperationKind::Sub { lhs, rhs, .. } => CallDef::Sub {
                    lhs: lhs.clone(),
                    rhs: rhs.clone(),
                },
                MirOperationKind::Copy { value, .. } => CallDef::Set {
                    value: value.clone(),
                },
                MirOperationKind::Cast { op, value, .. } => CallDef::Cast {
                    op: op.clone(),
                    value: value.clone(),
                },
                _ => continue,
            };
            defs.insert(result.clone(), def);
        }
    }

    defs
}

fn is_call_return_address_store(operation: &MirOperation, defs: &HashMap<String, CallDef>) -> bool {
    match &operation.kind {
        MirOperationKind::Store {
            address_space,
            address,
            value,
            ..
        } => {
            matches!(value, MirValue::Integer { .. })
                && matches!(
                    address_space,
                    MirAddressSpace::Default
                        | MirAddressSpace::Stack
                        | MirAddressSpace::ReturnAddress { .. }
                        | MirAddressSpace::Named { .. }
                )
                && is_stack_derived(address, defs)
        }
        _ => false,
    }
}

fn is_stack_derived(value: &MirValue, defs: &HashMap<String, CallDef>) -> bool {
    is_stack_derived_with_depth(value, defs, 0)
}

fn is_stack_derived_with_depth(
    value: &MirValue,
    defs: &HashMap<String, CallDef>,
    depth: usize,
) -> bool {
    if depth > 16 {
        return false;
    }

    match value {
        MirValue::Named { name, .. } if matches!(name.as_str(), "rsp" | "esp" | "sp") => true,
        MirValue::Named { name, .. } => match defs.get(name) {
            Some(CallDef::Add { lhs, rhs }) | Some(CallDef::Sub { lhs, rhs }) => {
                let lhs_stack = is_stack_derived_with_depth(lhs, defs, depth + 1);
                let rhs_stack = is_stack_derived_with_depth(rhs, defs, depth + 1);
                (lhs_stack && matches!(rhs, MirValue::Integer { .. }))
                    || (rhs_stack && matches!(lhs, MirValue::Integer { .. }))
            }
            Some(CallDef::Set { value }) => is_stack_derived_with_depth(value, defs, depth + 1),
            Some(CallDef::Cast { op, value }) if matches!(op, MirCastOperation::Bitcast) => {
                is_stack_derived_with_depth(value, defs, depth + 1)
            }
            _ => false,
        },
        _ => false,
    }
}

fn is_no_return_target(target: &MirControlTarget) -> bool {
    match target {
        MirControlTarget::Direct(target) => matches!(
            target.as_str(),
            "abort" | "exit" | "_exit" | "__stack_chk_fail" | "panic" | "panic_abort"
        ),
        MirControlTarget::FunctionIndirect(_) | MirControlTarget::BlockIndirect(_) => false,
    }
}
