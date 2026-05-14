use crate::ir::mir::{Mir, MirAddressSpace, MirOperationKind, MirType, MirValue};
use std::collections::HashMap;

type DefMap = HashMap<String, MirOperationKind>;

pub fn optimize_stack_slots(mir: &mut Mir) {
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
                    if !matches!(
                        address_space,
                        MirAddressSpace::Stack | MirAddressSpace::Default
                    ) {
                        continue;
                    }
                    let Some((base, offset, bits)) = resolve_stack_offset(address, &defs) else {
                        continue;
                    };
                    *address_space = stack_slot_space(&base, offset, bits);
                    *address = MirValue::integer(0, bits);
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

fn resolve_stack_offset(value: &MirValue, defs: &DefMap) -> Option<(String, i128, u16)> {
    resolve_stack_offset_with_depth(value, defs, 0)
}

fn resolve_stack_offset_with_depth(
    value: &MirValue,
    defs: &DefMap,
    depth: usize,
) -> Option<(String, i128, u16)> {
    if depth > 16 {
        return None;
    }

    match value {
        MirValue::Named { name, ty } if is_stack_base_name(name) => {
            Some((name.clone(), 0, integer_bits(ty).unwrap_or(64)))
        }
        MirValue::Named { name, ty } => match defs.get(name) {
            Some(MirOperationKind::Add { lhs, rhs, .. }) => {
                let bits = integer_bits(ty).unwrap_or(64);
                if let Some(offset) = integer_value(rhs) {
                    let (base, current, _) = resolve_stack_offset_with_depth(lhs, defs, depth + 1)?;
                    Some((base, current + offset, bits))
                } else if let Some(offset) = integer_value(lhs) {
                    let (base, current, _) = resolve_stack_offset_with_depth(rhs, defs, depth + 1)?;
                    Some((base, current + offset, bits))
                } else {
                    None
                }
            }
            Some(MirOperationKind::Sub { lhs, rhs, .. }) => {
                let bits = integer_bits(ty).unwrap_or(64);
                let offset = integer_value(rhs)?;
                let (base, current, _) = resolve_stack_offset_with_depth(lhs, defs, depth + 1)?;
                Some((base, current - offset, bits))
            }
            Some(MirOperationKind::Intrinsic {
                name, arguments, ..
            }) if name == "lir.set" && arguments.len() == 1 => {
                resolve_stack_offset_with_depth(&arguments[0], defs, depth + 1)
            }
            _ => None,
        },
        _ => None,
    }
}

fn stack_slot_space(base: &str, offset: i128, bits: u16) -> MirAddressSpace {
    let pointer_bytes = i128::from(bits.max(8) / 8);

    match base {
        "rbp" | "ebp" | "bp" | "fp" => {
            if offset < 0 {
                MirAddressSpace::local(format!("m{}", -offset))
            } else if offset == 0 {
                MirAddressSpace::saved_frame("frame_pointer".to_string())
            } else if offset == pointer_bytes {
                MirAddressSpace::return_address("retaddr".to_string())
            } else {
                MirAddressSpace::argument(format!("{}", offset - pointer_bytes))
            }
        }
        _ => {
            if offset < 0 {
                MirAddressSpace::spill(format!("m{}", -offset))
            } else if offset == 0 {
                MirAddressSpace::return_address("retaddr".to_string())
            } else {
                MirAddressSpace::incoming(format!("{}", offset))
            }
        }
    }
}

fn is_stack_base_name(name: &str) -> bool {
    matches!(name, "rsp" | "esp" | "sp" | "rbp" | "ebp" | "bp" | "fp")
}

fn integer_value(value: &MirValue) -> Option<i128> {
    match value {
        MirValue::Integer { value, .. } => Some(*value),
        _ => None,
    }
}

fn integer_bits(ty: &MirType) -> Option<u16> {
    match ty {
        MirType::Integer(bits) => Some(*bits),
        _ => None,
    }
}
