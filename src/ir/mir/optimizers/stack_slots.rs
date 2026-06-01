use crate::ir::mir::{Mir, MirAddressSpace, MirOperationKind, MirType, MirValue};
use std::collections::HashMap;

type DefMap = HashMap<String, MirOperationKind>;

pub fn optimize_stack_slots(mir: &mut Mir) {
    let defs = build_defs(mir);
    let frame_size = infer_stack_frame_size(mir);

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
                    *address_space = stack_slot_space(&base, offset, bits, frame_size);
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

fn infer_stack_frame_size(mir: &Mir) -> i128 {
    let mut frame_size = 0;

    for block in mir.blocks() {
        for operation in &block.operations {
            let Some(result) = operation.result.as_deref() else {
                continue;
            };
            if !is_stack_base_name(result) {
                continue;
            }

            match &operation.kind {
                MirOperationKind::Sub { lhs, rhs, .. } if is_named_stack_base(lhs, result) => {
                    if let Some(offset) = integer_value(rhs)
                        && offset > frame_size
                    {
                        frame_size = offset;
                    }
                }
                MirOperationKind::Add { lhs, rhs, .. } if is_named_stack_base(lhs, result) => {
                    if let Some(offset) = integer_value(rhs)
                        && offset < 0
                    {
                        frame_size = frame_size.max(-offset);
                    }
                }
                _ => {}
            }
        }
    }

    frame_size
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
            Some(MirOperationKind::Copy { value, .. }) => {
                resolve_stack_offset_with_depth(value, defs, depth + 1)
            }
            _ => None,
        },
        _ => None,
    }
}

fn stack_slot_space(base: &str, offset: i128, bits: u16, frame_size: i128) -> MirAddressSpace {
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
            if frame_size > 0 && offset > 0 {
                let frame_offset = offset - frame_size;
                if frame_offset < 0 {
                    MirAddressSpace::local(format!("m{}", -frame_offset))
                } else if frame_offset == 0 {
                    MirAddressSpace::return_address("retaddr".to_string())
                } else {
                    MirAddressSpace::incoming(format!("{}", frame_offset))
                }
            } else if offset < 0 {
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

fn is_named_stack_base(value: &MirValue, name: &str) -> bool {
    matches!(value, MirValue::Named { name: value_name, .. } if value_name == name)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::mir::{MirBlock, MirOperation};

    #[test]
    fn classifies_rsp_slots_inside_allocated_frame_as_locals() {
        let ty = MirType::integer(64);
        let mut mir = Mir::new(Some("test".to_string()));
        let mut block = MirBlock::new("entry".to_string());

        block.append_operation(MirOperation::new(
            Some("sp".to_string()),
            MirOperationKind::Sub {
                lhs: MirValue::named("sp".to_string(), ty.clone()),
                rhs: MirValue::integer(0xc0, 64),
                ty: ty.clone(),
            },
        ));
        block.append_operation(MirOperation::new(
            None,
            MirOperationKind::Store {
                address_space: MirAddressSpace::Default,
                address: MirValue::named("addr".to_string(), ty.clone()),
                value: MirValue::integer(0, 64),
                ty: ty.clone(),
            },
        ));
        block.append_operation(MirOperation::new(
            Some("addr".to_string()),
            MirOperationKind::Add {
                lhs: MirValue::named("sp".to_string(), ty.clone()),
                rhs: MirValue::integer(0xb0, 64),
                ty: ty.clone(),
            },
        ));
        block.append_operation(MirOperation::new(
            Some("load".to_string()),
            MirOperationKind::Load {
                address_space: MirAddressSpace::Default,
                address: MirValue::named("addr".to_string(), ty.clone()),
                ty,
            },
        ));
        mir.append_block(block);

        optimize_stack_slots(&mut mir);

        let operations = &mir.blocks()[0].operations;
        let MirOperationKind::Load {
            address_space,
            address,
            ..
        } = &operations[3].kind
        else {
            panic!("expected load");
        };
        assert_eq!(address_space, &MirAddressSpace::local("m16".to_string()));
        assert_eq!(address, &MirValue::integer(0, 64));
    }
}
