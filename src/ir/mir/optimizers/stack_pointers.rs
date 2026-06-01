use crate::ir::mir::{Mir, MirAddressSpace, MirOperationKind, MirType, MirValue};
use std::collections::HashMap;

type DefMap = HashMap<String, MirOperationKind>;

pub fn optimize_stack_pointers(mir: &mut Mir) {
    let defs = build_defs(mir);
    let frame_size = infer_stack_frame_size(mir);

    for block in mir.blocks_mut() {
        for operation in &mut block.operations {
            if let MirOperationKind::Call { arguments, .. } = &mut operation.kind {
                for argument in arguments {
                    if let Some(canonical) = canonical_stack_pointer(argument, &defs, frame_size) {
                        *argument = canonical;
                    }
                }
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

fn canonical_stack_pointer(value: &MirValue, defs: &DefMap, frame_size: i128) -> Option<MirValue> {
    if is_canonical_stack_pointer(value) {
        return None;
    }

    let (base, offset, bits) = resolve_stack_offset(value, defs, 0)?;
    let ty = value_type(value)?;
    let space = stack_slot_space(&base, offset, bits, frame_size);

    Some(MirValue::named(pointer_name(&space), ty))
}

fn is_canonical_stack_pointer(value: &MirValue) -> bool {
    matches!(value, MirValue::Named { name, .. } if name.starts_with("ptr."))
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

fn resolve_stack_offset(
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
                    let (base, current, _) = resolve_stack_offset(lhs, defs, depth + 1)?;
                    Some((base, current + offset, bits))
                } else if let Some(offset) = integer_value(lhs) {
                    let (base, current, _) = resolve_stack_offset(rhs, defs, depth + 1)?;
                    Some((base, current + offset, bits))
                } else {
                    None
                }
            }
            Some(MirOperationKind::Sub { lhs, rhs, .. }) => {
                let bits = integer_bits(ty).unwrap_or(64);
                let offset = integer_value(rhs)?;
                let (base, current, _) = resolve_stack_offset(lhs, defs, depth + 1)?;
                Some((base, current - offset, bits))
            }
            Some(MirOperationKind::Copy { value, .. }) => {
                resolve_stack_offset(value, defs, depth + 1)
            }
            Some(MirOperationKind::Cast { value, .. }) => {
                resolve_stack_offset(value, defs, depth + 1)
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

fn pointer_name(space: &MirAddressSpace) -> String {
    match space {
        MirAddressSpace::Local { name } => format!("ptr.local.{name}"),
        MirAddressSpace::Argument { name } => format!("ptr.argument.{name}"),
        MirAddressSpace::Spill { name } => format!("ptr.spill.{name}"),
        MirAddressSpace::Incoming { name } => format!("ptr.incoming.{name}"),
        MirAddressSpace::SavedFrame { name } => format!("ptr.saved_frame.{name}"),
        MirAddressSpace::ReturnAddress { name } => format!("ptr.return_address.{name}"),
        MirAddressSpace::Stack => "ptr.stack".to_string(),
        MirAddressSpace::Heap => "ptr.heap.anon".to_string(),
        MirAddressSpace::Global => "ptr.global.anon".to_string(),
        MirAddressSpace::HeapObject { name } => format!("ptr.heap.{name}"),
        MirAddressSpace::GlobalObject { name } => format!("ptr.global.{name}"),
        MirAddressSpace::Io => "ptr.io".to_string(),
        MirAddressSpace::Default => "ptr.default".to_string(),
        MirAddressSpace::Named { name } => format!("ptr.named.{name}"),
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
