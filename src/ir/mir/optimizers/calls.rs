use crate::ir::mir::analysis::build_use_def;
use crate::ir::mir::{Mir, MirAddressSpace, MirOperation, MirOperationKind, MirValue};
use std::collections::HashMap;

pub fn optimize_calls(mir: &mut Mir) {
    let uses = build_use_def(mir).uses;

    let defs = build_defs(mir);

    for block in mir.blocks_mut() {
        let mut normalized = Vec::with_capacity(block.operations.len());
        let mut no_return_call = false;

        for operation in std::mem::take(&mut block.operations) {
            if matches!(operation.kind, MirOperationKind::Call { .. }) {
                if normalized
                    .last()
                    .is_some_and(|previous| is_call_return_address_store(previous, &defs))
                {
                    normalized.pop();
                }
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
            block.terminator = Some(crate::ir::mir::MirTerminator::Unreachable);
        }
    }
}

fn build_defs(mir: &Mir) -> HashMap<String, MirOperationKind> {
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

fn is_call_return_address_store(
    operation: &MirOperation,
    defs: &HashMap<String, MirOperationKind>,
) -> bool {
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

fn is_stack_derived(value: &MirValue, defs: &HashMap<String, MirOperationKind>) -> bool {
    is_stack_derived_with_depth(value, defs, 0)
}

fn is_stack_derived_with_depth(
    value: &MirValue,
    defs: &HashMap<String, MirOperationKind>,
    depth: usize,
) -> bool {
    if depth > 16 {
        return false;
    }

    match value {
        MirValue::Named { name, .. } if matches!(name.as_str(), "rsp" | "esp" | "sp") => true,
        MirValue::Named { name, .. } => match defs.get(name) {
            Some(MirOperationKind::Add { lhs, rhs, .. })
            | Some(MirOperationKind::Sub { lhs, rhs, .. }) => {
                let lhs_stack = is_stack_derived_with_depth(lhs, defs, depth + 1);
                let rhs_stack = is_stack_derived_with_depth(rhs, defs, depth + 1);
                (lhs_stack && matches!(rhs, MirValue::Integer { .. }))
                    || (rhs_stack && matches!(lhs, MirValue::Integer { .. }))
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

fn is_no_return_target(target: &str) -> bool {
    matches!(
        target,
        "abort" | "exit" | "_exit" | "__stack_chk_fail" | "panic" | "panic_abort"
    )
}
