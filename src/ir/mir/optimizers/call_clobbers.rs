use crate::ir::lir::{LirAbi, LirCpuKind};
use crate::ir::mir::{Mir, MirAddressSpace, MirCallClobber, MirOperationKind, MirType, MirValue};
use std::collections::HashMap;

pub fn optimize_call_clobbers(mir: &mut Mir) {
    let defs = build_defs(mir);
    let clobbers = mir
        .abi
        .as_ref()
        .map(caller_saved_registers)
        .unwrap_or_default();
    let default_memory_effects = mir
        .abi
        .as_ref()
        .map(call_memory_effects)
        .unwrap_or_default();

    for block in mir.blocks_mut() {
        for operation in &mut block.operations {
            if let MirOperationKind::Call {
                arguments,
                clobbers: existing_clobbers,
                memory_effects: existing_effects,
                ..
            } = &mut operation.kind
            {
                merge_clobbers(existing_clobbers, &clobbers);

                let mut memory_effects = default_memory_effects.clone();
                for argument in arguments.iter() {
                    extend_unique(
                        &mut memory_effects,
                        infer_argument_memory_effects(argument, &defs),
                    );
                }
                merge_address_spaces(existing_effects, memory_effects);
            }
        }
    }
}

type DefMap = HashMap<String, MirOperationKind>;

fn caller_saved_registers(abi: &LirAbi) -> Vec<MirCallClobber> {
    let registers: Vec<(String, u16)> = match (abi.name.as_str(), abi.cpu.kind()) {
        ("sysv", Some(LirCpuKind::Amd64)) => vec![
            ("rcx".to_string(), 64),
            ("rdx".to_string(), 64),
            ("rsi".to_string(), 64),
            ("rdi".to_string(), 64),
            ("r8".to_string(), 64),
            ("r9".to_string(), 64),
            ("r10".to_string(), 64),
            ("r11".to_string(), 64),
        ],
        ("windows64", Some(LirCpuKind::Amd64)) => vec![
            ("rcx".to_string(), 64),
            ("rdx".to_string(), 64),
            ("r8".to_string(), 64),
            ("r9".to_string(), 64),
            ("r10".to_string(), 64),
            ("r11".to_string(), 64),
        ],
        ("cdecl", Some(LirCpuKind::I386))
        | ("stdcall", Some(LirCpuKind::I386))
        | ("fastcall", Some(LirCpuKind::I386)) => {
            vec![("ecx".to_string(), 32), ("edx".to_string(), 32)]
        }
        ("sysv", Some(LirCpuKind::Arm64)) | ("windows64", Some(LirCpuKind::Arm64)) => {
            (1..=17).map(|index| (format!("x{index}"), 64)).collect()
        }
        _ => Vec::new(),
    };

    registers
        .into_iter()
        .map(|(register, bits)| MirCallClobber {
            register,
            ty: MirType::integer(bits),
        })
        .collect()
}

fn call_memory_effects(abi: &LirAbi) -> Vec<MirAddressSpace> {
    match abi.name.as_str() {
        "linux_syscall" | "windows_syscall" => vec![
            MirAddressSpace::return_address("retaddr".to_string()),
            MirAddressSpace::incoming("syscall".to_string()),
            MirAddressSpace::heap(),
            MirAddressSpace::global(),
            MirAddressSpace::io(),
        ],
        _ => vec![
            MirAddressSpace::return_address("retaddr".to_string()),
            MirAddressSpace::incoming("args".to_string()),
        ],
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

fn merge_clobbers(existing: &mut Vec<MirCallClobber>, additions: &[MirCallClobber]) {
    for clobber in additions {
        if !existing.contains(clobber) {
            existing.push(clobber.clone());
        }
    }
}

fn merge_address_spaces(existing: &mut Vec<MirAddressSpace>, additions: Vec<MirAddressSpace>) {
    extend_unique(existing, additions);
}

fn extend_unique(values: &mut Vec<MirAddressSpace>, additions: Vec<MirAddressSpace>) {
    for addition in additions {
        if !values.contains(&addition) {
            values.push(addition);
        }
    }
}

fn infer_argument_memory_effects(argument: &MirValue, defs: &DefMap) -> Vec<MirAddressSpace> {
    let mut effects = Vec::new();

    if let Some(space) = resolve_canonical_pointer_region(argument, defs, 0) {
        effects.push(space);
    } else if let Some(space) = resolve_argument_region(argument, defs) {
        effects.push(space);
    } else if let Some(base) = resolve_stack_base(argument, defs, 0) {
        effects.push(base);
    }

    effects
}

fn parse_pointer_region_name(name: &str) -> Option<MirAddressSpace> {
    let rest = name.strip_prefix("ptr.")?;
    let (kind, value) = rest.split_once('.')?;
    match kind {
        "local" => Some(MirAddressSpace::local(value.to_string())),
        "argument" => Some(MirAddressSpace::argument(value.to_string())),
        "spill" => Some(MirAddressSpace::spill(value.to_string())),
        "incoming" => Some(MirAddressSpace::incoming(value.to_string())),
        "saved_frame" => Some(MirAddressSpace::saved_frame(value.to_string())),
        "return_address" => Some(MirAddressSpace::return_address(value.to_string())),
        "stack" => Some(MirAddressSpace::stack()),
        "heap" => Some(MirAddressSpace::heap_object(value.to_string())),
        "global" => Some(MirAddressSpace::global_object(value.to_string())),
        "io" => Some(MirAddressSpace::io()),
        "default" => Some(MirAddressSpace::default_space()),
        "named" => Some(MirAddressSpace::named(value.to_string())),
        _ => None,
    }
}

fn resolve_canonical_pointer_region(
    value: &MirValue,
    defs: &DefMap,
    depth: usize,
) -> Option<MirAddressSpace> {
    if depth > 16 {
        return None;
    }

    match value {
        MirValue::Named { name, .. } => {
            if let Some(space) = parse_pointer_region_name(name) {
                return Some(space);
            }

            match defs.get(name) {
                Some(MirOperationKind::Intrinsic {
                    name, arguments, ..
                }) if name == "lir.set" && arguments.len() == 1 => {
                    resolve_canonical_pointer_region(&arguments[0], defs, depth + 1)
                }
                Some(MirOperationKind::Cast { value, .. }) => {
                    resolve_canonical_pointer_region(value, defs, depth + 1)
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn resolve_argument_region(value: &MirValue, defs: &DefMap) -> Option<MirAddressSpace> {
    let (base, offset, bits) = resolve_stack_offset(value, defs, 0)?;
    Some(stack_slot_space(&base, offset, bits))
}

fn resolve_stack_base(value: &MirValue, defs: &DefMap, depth: usize) -> Option<MirAddressSpace> {
    if depth > 16 {
        return None;
    }

    match value {
        MirValue::Named { name, .. } if is_stack_base_name(name) => Some(MirAddressSpace::stack()),
        MirValue::Named { name, .. } => match defs.get(name) {
            Some(MirOperationKind::Intrinsic {
                name, arguments, ..
            }) if name == "lir.set" && arguments.len() == 1 => {
                resolve_stack_base(&arguments[0], defs, depth + 1)
            }
            Some(MirOperationKind::Cast { value, .. }) => {
                resolve_stack_base(value, defs, depth + 1)
            }
            Some(MirOperationKind::Add { lhs, rhs, .. })
            | Some(MirOperationKind::Sub { lhs, rhs, .. }) => {
                resolve_stack_base(lhs, defs, depth + 1)
                    .or_else(|| resolve_stack_base(rhs, defs, depth + 1))
            }
            _ => None,
        },
        _ => None,
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
            Some(MirOperationKind::Intrinsic {
                name, arguments, ..
            }) if name == "lir.set" && arguments.len() == 1 => {
                resolve_stack_offset(&arguments[0], defs, depth + 1)
            }
            Some(MirOperationKind::Cast { value, .. }) => {
                resolve_stack_offset(value, defs, depth + 1)
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
