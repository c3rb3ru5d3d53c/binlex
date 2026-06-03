use crate::ir::lir::{
    Lir, LirEffect, LirExpression, LirLocation, LirTemporary, LirTerminator,
    normalize_instruction_lir, validate_instruction_lir,
};
use std::collections::{HashMap, HashSet};
use std::io::Error;

fn expression_bits(expression: &LirExpression) -> u16 {
    match expression {
        LirExpression::Const { bits, .. }
        | LirExpression::Function { bits, .. }
        | LirExpression::DataAddress { bits, .. }
        | LirExpression::AddressOf { bits, .. }
        | LirExpression::Load { bits, .. }
        | LirExpression::Unary { bits, .. }
        | LirExpression::Binary { bits, .. }
        | LirExpression::Cast { bits, .. }
        | LirExpression::Compare { bits, .. }
        | LirExpression::Select { bits, .. }
        | LirExpression::Extract { bits, .. }
        | LirExpression::Concat { bits, .. }
        | LirExpression::Undefined { bits }
        | LirExpression::Poison { bits }
        | LirExpression::Intrinsic { bits, .. }
        | LirExpression::Null { bits }
        | LirExpression::Allocate { bits, .. }
        | LirExpression::ReadProperty { bits, .. }
        | LirExpression::ReadElement { bits, .. } => *bits,
        LirExpression::Read(location) => match location.as_ref() {
            crate::ir::lir::LirLocation::Register { bits, .. }
            | crate::ir::lir::LirLocation::Flag { bits, .. }
            | crate::ir::lir::LirLocation::ProgramCounter { bits }
            | crate::ir::lir::LirLocation::Temporary { bits, .. }
            | crate::ir::lir::LirLocation::Memory { bits, .. }
            | crate::ir::lir::LirLocation::IndexedMemory { bits, .. }
            | crate::ir::lir::LirLocation::StackMemory { bits, .. } => *bits,
        },
    }
}

fn coerce_expression_width(expression: LirExpression, bits: u16) -> LirExpression {
    let current_bits = expression_bits(&expression);
    if current_bits == bits {
        return expression;
    }

    if current_bits < bits {
        LirExpression::Cast {
            op: crate::ir::lir::LirOperationCast::ZeroExtend,
            arg: Box::new(expression),
            bits,
        }
    } else {
        LirExpression::Cast {
            op: crate::ir::lir::LirOperationCast::Truncate,
            arg: Box::new(expression),
            bits,
        }
    }
}

fn normalize_shift_binary(
    op: crate::ir::lir::LirOperationBinary,
    left: LirExpression,
    right: LirExpression,
    bits: u16,
) -> (LirExpression, LirExpression) {
    match op {
        crate::ir::lir::LirOperationBinary::Shl
        | crate::ir::lir::LirOperationBinary::LShr
        | crate::ir::lir::LirOperationBinary::AShr => (left, coerce_expression_width(right, bits)),
        _ => (left, right),
    }
}

fn normalize_binary(
    op: crate::ir::lir::LirOperationBinary,
    left: LirExpression,
    right: LirExpression,
    bits: u16,
) -> (LirExpression, LirExpression) {
    let left = coerce_expression_width(left, bits);
    let right = coerce_expression_width(right, bits);
    normalize_shift_binary(op, left, right, bits)
}

fn normalize_compare(left: LirExpression, right: LirExpression) -> (LirExpression, LirExpression) {
    let left_bits = expression_bits(&left);
    let right_bits = expression_bits(&right);
    if left_bits == right_bits {
        return (left, right);
    }

    match (&left, &right) {
        (LirExpression::Const { .. }, _) => (coerce_expression_width(left, right_bits), right),
        (_, LirExpression::Const { .. }) => (left, coerce_expression_width(right, left_bits)),
        _ => (left, coerce_expression_width(right, left_bits)),
    }
}

pub fn prepare_instruction_semantics(semantics: &Lir) -> Result<Lir, Error> {
    validate_instruction_lir(semantics)?;
    let normalized = normalize_instruction_lir(semantics);
    let (temporaries, snapshot_effects, effects, snapshots, load_snapshots) =
        snapshot_written_locations(&normalized);
    Ok(Lir {
        version: normalized.version,
        status: normalized.status,
        metadata: Default::default(),
        abi: normalized.abi,
        encoding: normalized.encoding.clone(),
        temporaries,
        effects: snapshot_effects
            .iter()
            .map(|effect| prepare_effect(effect, &HashMap::new(), &HashMap::new()))
            .chain(
                effects
                    .iter()
                    .map(|effect| prepare_effect(effect, &snapshots, &load_snapshots)),
            )
            .collect(),
        terminator: prepare_terminator(&normalized.terminator, &snapshots, &load_snapshots),
        diagnostics: normalized.diagnostics,
    })
}

fn snapshot_written_locations(
    semantics: &Lir,
) -> (
    Vec<LirTemporary>,
    Vec<LirEffect>,
    Vec<LirEffect>,
    HashMap<LirLocation, LirLocation>,
    HashMap<LirExpression, LirLocation>,
) {
    let mut temporaries = semantics.temporaries.clone();
    let mut snapshots = HashMap::<LirLocation, LirLocation>::new();
    let mut load_snapshots = HashMap::<LirExpression, LirLocation>::new();
    let read_locations = collect_read_locations(semantics);
    let read_loads = collect_read_loads(semantics);
    let written_loads = collect_written_loads(semantics);
    let mut next_temp_id = temporaries.iter().map(|temp| temp.id).max().unwrap_or(0);
    let mut snapshot_effects = Vec::<LirEffect>::new();

    for effect in &semantics.effects {
        if let LirEffect::Set { dst, .. } = effect {
            let should_snapshot = matches!(
                dst,
                LirLocation::Register { .. }
                    | LirLocation::Flag { .. }
                    | LirLocation::ProgramCounter { .. }
            ) && read_locations.contains(dst);
            if should_snapshot && !snapshots.contains_key(dst) {
                next_temp_id += 1;
                let bits = match dst {
                    LirLocation::Register { bits, .. } => *bits,
                    LirLocation::Flag { bits, .. } => *bits,
                    LirLocation::ProgramCounter { bits } => *bits,
                    _ => 0,
                };
                let temp = LirLocation::Temporary {
                    id: next_temp_id,
                    bits,
                };
                temporaries.push(LirTemporary {
                    id: next_temp_id,
                    bits,
                    name: Some(format!("snapshot_{}", snapshots.len())),
                });
                snapshot_effects.push(LirEffect::Set {
                    dst: temp.clone(),
                    expression: LirExpression::Read(Box::new(dst.clone())),
                });
                snapshots.insert(dst.clone(), temp);
            }
        }
    }

    for load in read_loads {
        if written_loads.contains(&load) && !load_snapshots.contains_key(&load) {
            next_temp_id += 1;
            let bits = match &load {
                LirExpression::Load { bits, .. } => *bits,
                _ => continue,
            };
            let temp = LirLocation::Temporary {
                id: next_temp_id,
                bits,
            };
            temporaries.push(LirTemporary {
                id: next_temp_id,
                bits,
                name: Some(format!("load_snapshot_{}", load_snapshots.len())),
            });
            snapshot_effects.push(LirEffect::Set {
                dst: temp.clone(),
                expression: load.clone(),
            });
            load_snapshots.insert(load, temp);
        }
    }

    (
        temporaries,
        snapshot_effects,
        semantics.effects.clone(),
        snapshots,
        load_snapshots,
    )
}

fn collect_read_locations(semantics: &Lir) -> HashSet<LirLocation> {
    let mut reads = HashSet::new();
    for effect in &semantics.effects {
        collect_effect_reads(effect, &mut reads);
    }
    collect_terminator_reads(&semantics.terminator, &mut reads);
    reads
}

fn collect_read_loads(semantics: &Lir) -> HashSet<LirExpression> {
    let mut reads = HashSet::new();
    for effect in &semantics.effects {
        collect_effect_loads(effect, &mut reads);
    }
    collect_terminator_loads(&semantics.terminator, &mut reads);
    reads
}

fn collect_written_loads(semantics: &Lir) -> HashSet<LirExpression> {
    let mut writes = HashSet::new();
    for effect in &semantics.effects {
        match effect {
            LirEffect::Set { dst, .. } => {
                if let LirLocation::Memory { space, addr, bits } = dst {
                    writes.insert(LirExpression::Load {
                        space: space.clone(),
                        addr: addr.clone(),
                        bits: *bits,
                    });
                }
            }
            LirEffect::Store {
                space, addr, bits, ..
            } => {
                writes.insert(LirExpression::Load {
                    space: space.clone(),
                    addr: Box::new(addr.clone()),
                    bits: *bits,
                });
            }
            LirEffect::AtomicCmpXchg {
                space, addr, bits, ..
            } => {
                writes.insert(LirExpression::Load {
                    space: space.clone(),
                    addr: Box::new(addr.clone()),
                    bits: *bits,
                });
            }
            LirEffect::Push { .. } | LirEffect::Pop { .. } => {}
            _ => {}
        }
    }
    writes
}

fn collect_effect_reads(effect: &LirEffect, reads: &mut HashSet<LirLocation>) {
    match effect {
        LirEffect::Set { expression, .. } => collect_expression_reads(expression, reads),
        LirEffect::Store {
            addr, expression, ..
        } => {
            collect_expression_reads(addr, reads);
            collect_expression_reads(expression, reads);
        }
        LirEffect::MemorySet {
            addr,
            value,
            count,
            decrement,
            ..
        } => {
            collect_expression_reads(addr, reads);
            collect_expression_reads(value, reads);
            collect_expression_reads(count, reads);
            collect_expression_reads(decrement, reads);
        }
        LirEffect::MemoryCopy {
            src_addr,
            dst_addr,
            count,
            decrement,
            ..
        } => {
            collect_expression_reads(src_addr, reads);
            collect_expression_reads(dst_addr, reads);
            collect_expression_reads(count, reads);
            collect_expression_reads(decrement, reads);
        }
        LirEffect::AtomicCmpXchg {
            addr,
            expected,
            desired,
            ..
        } => {
            collect_expression_reads(addr, reads);
            collect_expression_reads(expected, reads);
            collect_expression_reads(desired, reads);
        }
        LirEffect::WriteProperty {
            reference,
            expression,
            ..
        } => {
            collect_expression_reads(reference, reads);
            collect_expression_reads(expression, reads);
        }
        LirEffect::WriteElement {
            reference,
            index,
            expression,
            ..
        } => {
            collect_expression_reads(reference, reads);
            collect_expression_reads(index, reads);
            collect_expression_reads(expression, reads);
        }
        LirEffect::Push { expression, .. } => collect_expression_reads(expression, reads),
        LirEffect::Pop { .. } => {}
        LirEffect::Intrinsic { args, .. } => {
            for arg in args {
                collect_expression_reads(arg, reads);
            }
        }
        LirEffect::Fence { .. } | LirEffect::Trap { .. } | LirEffect::Nop => {}
    }
}

fn collect_effect_loads(effect: &LirEffect, reads: &mut HashSet<LirExpression>) {
    match effect {
        LirEffect::Set { expression, .. } => collect_expression_loads(expression, reads),
        LirEffect::Store {
            addr, expression, ..
        } => {
            collect_expression_loads(addr, reads);
            collect_expression_loads(expression, reads);
        }
        LirEffect::MemorySet {
            addr,
            value,
            count,
            decrement,
            ..
        } => {
            collect_expression_loads(addr, reads);
            collect_expression_loads(value, reads);
            collect_expression_loads(count, reads);
            collect_expression_loads(decrement, reads);
        }
        LirEffect::MemoryCopy {
            src_addr,
            dst_addr,
            count,
            decrement,
            ..
        } => {
            collect_expression_loads(src_addr, reads);
            collect_expression_loads(dst_addr, reads);
            collect_expression_loads(count, reads);
            collect_expression_loads(decrement, reads);
        }
        LirEffect::AtomicCmpXchg {
            addr,
            expected,
            desired,
            ..
        } => {
            collect_expression_loads(addr, reads);
            collect_expression_loads(expected, reads);
            collect_expression_loads(desired, reads);
        }
        LirEffect::WriteProperty {
            reference,
            expression,
            ..
        } => {
            collect_expression_loads(reference, reads);
            collect_expression_loads(expression, reads);
        }
        LirEffect::WriteElement {
            reference,
            index,
            expression,
            ..
        } => {
            collect_expression_loads(reference, reads);
            collect_expression_loads(index, reads);
            collect_expression_loads(expression, reads);
        }
        LirEffect::Push { expression, .. } => collect_expression_loads(expression, reads),
        LirEffect::Pop { .. } => {}
        LirEffect::Intrinsic { args, .. } => {
            for arg in args {
                collect_expression_loads(arg, reads);
            }
        }
        LirEffect::Fence { .. } | LirEffect::Trap { .. } | LirEffect::Nop => {}
    }
}

fn collect_terminator_reads(terminator: &LirTerminator, reads: &mut HashSet<LirLocation>) {
    match terminator {
        LirTerminator::Jump { target } => collect_expression_reads(target, reads),
        LirTerminator::Branch {
            condition,
            true_target,
            false_target,
        } => {
            collect_expression_reads(condition, reads);
            collect_expression_reads(true_target, reads);
            collect_expression_reads(false_target, reads);
        }
        LirTerminator::Call {
            target,
            return_target,
            ..
        } => {
            collect_expression_reads(target, reads);
            if let Some(return_target) = return_target {
                collect_expression_reads(return_target, reads);
            }
        }
        LirTerminator::Return { expression } => {
            if let Some(expression) = expression {
                collect_expression_reads(expression, reads);
            }
        }
        LirTerminator::FallThrough | LirTerminator::Unreachable | LirTerminator::Trap => {}
    }
}

fn collect_terminator_loads(terminator: &LirTerminator, reads: &mut HashSet<LirExpression>) {
    match terminator {
        LirTerminator::Jump { target } => collect_expression_loads(target, reads),
        LirTerminator::Branch {
            condition,
            true_target,
            false_target,
        } => {
            collect_expression_loads(condition, reads);
            collect_expression_loads(true_target, reads);
            collect_expression_loads(false_target, reads);
        }
        LirTerminator::Call {
            target,
            return_target,
            ..
        } => {
            collect_expression_loads(target, reads);
            if let Some(return_target) = return_target {
                collect_expression_loads(return_target, reads);
            }
        }
        LirTerminator::Return { expression } => {
            if let Some(expression) = expression {
                collect_expression_loads(expression, reads);
            }
        }
        LirTerminator::FallThrough | LirTerminator::Unreachable | LirTerminator::Trap => {}
    }
}

fn collect_expression_reads(expression: &LirExpression, reads: &mut HashSet<LirLocation>) {
    match expression {
        LirExpression::Function { .. } => {}
        LirExpression::DataAddress { .. } => {}
        LirExpression::AddressOf { .. } => {}
        LirExpression::Read(location) => {
            reads.insert(location.as_ref().clone());
        }
        LirExpression::Load { addr, .. } => collect_expression_reads(addr, reads),
        LirExpression::Unary { arg, .. } => collect_expression_reads(arg, reads),
        LirExpression::Binary { left, right, .. } => {
            collect_expression_reads(left, reads);
            collect_expression_reads(right, reads);
        }
        LirExpression::Compare { left, right, .. } => {
            collect_expression_reads(left, reads);
            collect_expression_reads(right, reads);
        }
        LirExpression::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            collect_expression_reads(condition, reads);
            collect_expression_reads(when_true, reads);
            collect_expression_reads(when_false, reads);
        }
        LirExpression::Cast { arg, .. } | LirExpression::Extract { arg, .. } => {
            collect_expression_reads(arg, reads)
        }
        LirExpression::ReadProperty { reference, .. } => collect_expression_reads(reference, reads),
        LirExpression::ReadElement {
            reference, index, ..
        } => {
            collect_expression_reads(reference, reads);
            collect_expression_reads(index, reads);
        }
        LirExpression::Concat { parts, .. } => {
            for part in parts {
                collect_expression_reads(part, reads);
            }
        }
        LirExpression::Intrinsic { args, .. } => {
            for arg in args {
                collect_expression_reads(arg, reads);
            }
        }
        LirExpression::Const { .. }
        | LirExpression::Undefined { .. }
        | LirExpression::Poison { .. }
        | LirExpression::Null { .. }
        | LirExpression::Allocate { .. } => {}
    }
}

fn collect_expression_loads(expression: &LirExpression, reads: &mut HashSet<LirExpression>) {
    match expression {
        LirExpression::Read(_) => {}
        LirExpression::Function { .. } => {}
        LirExpression::DataAddress { .. } => {}
        LirExpression::AddressOf { .. } => {}
        LirExpression::Load { space, addr, bits } => {
            reads.insert(LirExpression::Load {
                space: space.clone(),
                addr: Box::new((**addr).clone()),
                bits: *bits,
            });
            collect_expression_loads(addr, reads);
        }
        LirExpression::Unary { arg, .. }
        | LirExpression::Cast { arg, .. }
        | LirExpression::Extract { arg, .. } => collect_expression_loads(arg, reads),
        LirExpression::ReadProperty { reference, .. } => collect_expression_loads(reference, reads),
        LirExpression::ReadElement {
            reference, index, ..
        } => {
            collect_expression_loads(reference, reads);
            collect_expression_loads(index, reads);
        }
        LirExpression::Binary { left, right, .. } | LirExpression::Compare { left, right, .. } => {
            collect_expression_loads(left, reads);
            collect_expression_loads(right, reads);
        }
        LirExpression::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            collect_expression_loads(condition, reads);
            collect_expression_loads(when_true, reads);
            collect_expression_loads(when_false, reads);
        }
        LirExpression::Concat { parts, .. } => {
            for part in parts {
                collect_expression_loads(part, reads);
            }
        }
        LirExpression::Intrinsic { args, .. } => {
            for arg in args {
                collect_expression_loads(arg, reads);
            }
        }
        LirExpression::Const { .. }
        | LirExpression::Undefined { .. }
        | LirExpression::Poison { .. }
        | LirExpression::Null { .. }
        | LirExpression::Allocate { .. } => {}
    }
}

fn prepare_effect(
    effect: &LirEffect,
    snapshots: &HashMap<LirLocation, LirLocation>,
    load_snapshots: &HashMap<LirExpression, LirLocation>,
) -> LirEffect {
    match effect {
        LirEffect::Set { dst, expression } => match dst {
            crate::ir::lir::LirLocation::Memory { bits, .. } => LirEffect::Set {
                dst: dst.clone(),
                expression: prepare_expression(
                    &coerce_expression_width(expression.clone(), *bits),
                    snapshots,
                    load_snapshots,
                ),
            },
            _ => LirEffect::Set {
                dst: dst.clone(),
                expression: prepare_expression(expression, snapshots, load_snapshots),
            },
        },
        LirEffect::Store {
            space,
            addr,
            expression,
            bits,
        } => LirEffect::Store {
            space: space.clone(),
            addr: prepare_expression(addr, snapshots, load_snapshots),
            expression: prepare_expression(
                &coerce_expression_width(expression.clone(), *bits),
                snapshots,
                load_snapshots,
            ),
            bits: *bits,
        },
        LirEffect::MemorySet {
            space,
            addr,
            value,
            count,
            element_bits,
            decrement,
        } => LirEffect::MemorySet {
            space: space.clone(),
            addr: prepare_expression(addr, snapshots, load_snapshots),
            value: prepare_expression(
                &coerce_expression_width(value.clone(), *element_bits),
                snapshots,
                load_snapshots,
            ),
            count: prepare_expression(count, snapshots, load_snapshots),
            element_bits: *element_bits,
            decrement: prepare_expression(decrement, snapshots, load_snapshots),
        },
        LirEffect::MemoryCopy {
            src_space,
            src_addr,
            dst_space,
            dst_addr,
            count,
            element_bits,
            decrement,
        } => LirEffect::MemoryCopy {
            src_space: src_space.clone(),
            src_addr: prepare_expression(src_addr, snapshots, load_snapshots),
            dst_space: dst_space.clone(),
            dst_addr: prepare_expression(dst_addr, snapshots, load_snapshots),
            count: prepare_expression(count, snapshots, load_snapshots),
            element_bits: *element_bits,
            decrement: prepare_expression(decrement, snapshots, load_snapshots),
        },
        LirEffect::AtomicCmpXchg {
            space,
            addr,
            expected,
            desired,
            bits,
            observed,
        } => LirEffect::AtomicCmpXchg {
            space: space.clone(),
            addr: prepare_expression(addr, snapshots, load_snapshots),
            expected: prepare_expression(
                &coerce_expression_width(expected.clone(), *bits),
                snapshots,
                load_snapshots,
            ),
            desired: prepare_expression(
                &coerce_expression_width(desired.clone(), *bits),
                snapshots,
                load_snapshots,
            ),
            bits: *bits,
            observed: observed.clone(),
        },
        LirEffect::WriteProperty {
            reference,
            name,
            expression,
            bits,
        } => LirEffect::WriteProperty {
            reference: prepare_expression(reference, snapshots, load_snapshots),
            name: name.clone(),
            expression: prepare_expression(
                &coerce_expression_width(expression.clone(), *bits),
                snapshots,
                load_snapshots,
            ),
            bits: *bits,
        },
        LirEffect::WriteElement {
            reference,
            index,
            expression,
            bits,
        } => LirEffect::WriteElement {
            reference: prepare_expression(reference, snapshots, load_snapshots),
            index: prepare_expression(index, snapshots, load_snapshots),
            expression: prepare_expression(
                &coerce_expression_width(expression.clone(), *bits),
                snapshots,
                load_snapshots,
            ),
            bits: *bits,
        },
        LirEffect::Push { stack, expression } => LirEffect::Push {
            stack: stack.clone(),
            expression: prepare_expression(expression, snapshots, load_snapshots),
        },
        LirEffect::Pop { stack, dst } => LirEffect::Pop {
            stack: stack.clone(),
            dst: dst.clone(),
        },
        LirEffect::Fence { kind } => LirEffect::Fence { kind: kind.clone() },
        LirEffect::Trap { kind } => LirEffect::Trap { kind: kind.clone() },
        LirEffect::Intrinsic {
            name,
            args,
            outputs,
        } => LirEffect::Intrinsic {
            name: name.clone(),
            args: args
                .iter()
                .map(|expression| prepare_expression(expression, snapshots, load_snapshots))
                .collect(),
            outputs: outputs.clone(),
        },
        LirEffect::Nop => LirEffect::Nop,
    }
}

fn prepare_terminator(
    terminator: &LirTerminator,
    snapshots: &HashMap<LirLocation, LirLocation>,
    load_snapshots: &HashMap<LirExpression, LirLocation>,
) -> LirTerminator {
    match terminator {
        LirTerminator::FallThrough => LirTerminator::FallThrough,
        LirTerminator::Jump { target } => LirTerminator::Jump {
            target: prepare_expression(target, snapshots, load_snapshots),
        },
        LirTerminator::Branch {
            condition,
            true_target,
            false_target,
        } => LirTerminator::Branch {
            condition: prepare_expression(condition, snapshots, load_snapshots),
            true_target: prepare_expression(true_target, snapshots, load_snapshots),
            false_target: prepare_expression(false_target, snapshots, load_snapshots),
        },
        LirTerminator::Call {
            target,
            return_target,
            does_return,
        } => LirTerminator::Call {
            target: prepare_expression(target, snapshots, load_snapshots),
            return_target: return_target
                .as_ref()
                .map(|expression| prepare_expression(expression, snapshots, load_snapshots)),
            does_return: *does_return,
        },
        LirTerminator::Return { expression } => LirTerminator::Return {
            expression: expression
                .as_ref()
                .map(|expression| prepare_expression(expression, snapshots, load_snapshots)),
        },
        LirTerminator::Unreachable => LirTerminator::Unreachable,
        LirTerminator::Trap => LirTerminator::Trap,
    }
}

fn prepare_location(
    location: &LirLocation,
    snapshots: &HashMap<LirLocation, LirLocation>,
    load_snapshots: &HashMap<LirExpression, LirLocation>,
) -> LirLocation {
    if let Some(snapshot) = snapshots.get(location) {
        return snapshot.clone();
    }
    match location {
        LirLocation::Memory { space, addr, bits } => LirLocation::Memory {
            space: space.clone(),
            addr: Box::new(prepare_expression(addr, snapshots, load_snapshots)),
            bits: *bits,
        },
        LirLocation::IndexedMemory { name, index, bits } => LirLocation::IndexedMemory {
            name: name.clone(),
            index: Box::new(prepare_expression(index, snapshots, load_snapshots)),
            bits: *bits,
        },
        LirLocation::Register { .. }
        | LirLocation::Flag { .. }
        | LirLocation::ProgramCounter { .. }
        | LirLocation::Temporary { .. }
        | LirLocation::StackMemory { .. } => location.clone(),
    }
}

fn prepare_expression(
    expression: &LirExpression,
    snapshots: &HashMap<LirLocation, LirLocation>,
    load_snapshots: &HashMap<LirExpression, LirLocation>,
) -> LirExpression {
    match expression {
        LirExpression::Const { value, bits } => LirExpression::Const {
            value: *value,
            bits: *bits,
        },
        LirExpression::Function { name, bits } => LirExpression::Function {
            name: name.clone(),
            bits: *bits,
        },
        LirExpression::DataAddress { name, bits } => LirExpression::DataAddress {
            name: name.clone(),
            bits: *bits,
        },
        LirExpression::AddressOf { location, bits } => LirExpression::AddressOf {
            location: Box::new(prepare_location(location, snapshots, load_snapshots)),
            bits: *bits,
        },
        LirExpression::Read(location) => LirExpression::Read(Box::new(
            snapshots
                .get(location.as_ref())
                .cloned()
                .unwrap_or_else(|| location.as_ref().clone()),
        )),
        LirExpression::Load { space, addr, bits } => {
            let prepared = LirExpression::Load {
                space: space.clone(),
                addr: Box::new(prepare_expression(addr, snapshots, load_snapshots)),
                bits: *bits,
            };
            if let Some(snapshot) = load_snapshots.get(&prepared) {
                LirExpression::Read(Box::new(snapshot.clone()))
            } else {
                prepared
            }
        }
        LirExpression::Unary { op, arg, bits } => LirExpression::Unary {
            op: *op,
            arg: Box::new(prepare_expression(arg, snapshots, load_snapshots)),
            bits: *bits,
        },
        LirExpression::Binary {
            op,
            left,
            right,
            bits,
        } => {
            let left = prepare_expression(left, snapshots, load_snapshots);
            let right = prepare_expression(right, snapshots, load_snapshots);
            let (left, right) = normalize_binary(*op, left, right, *bits);
            LirExpression::Binary {
                op: *op,
                left: Box::new(left),
                right: Box::new(right),
                bits: *bits,
            }
        }
        LirExpression::Cast { op, arg, bits } => LirExpression::Cast {
            op: *op,
            arg: Box::new(prepare_expression(arg, snapshots, load_snapshots)),
            bits: *bits,
        },
        LirExpression::Compare {
            op,
            left,
            right,
            bits,
        } => {
            let left = prepare_expression(left, snapshots, load_snapshots);
            let right = prepare_expression(right, snapshots, load_snapshots);
            let (left, right) = normalize_compare(left, right);
            LirExpression::Compare {
                op: *op,
                left: Box::new(left),
                right: Box::new(right),
                bits: *bits,
            }
        }
        LirExpression::Select {
            condition,
            when_true,
            when_false,
            bits,
        } => LirExpression::Select {
            condition: Box::new(prepare_expression(condition, snapshots, load_snapshots)),
            when_true: Box::new(prepare_expression(when_true, snapshots, load_snapshots)),
            when_false: Box::new(prepare_expression(when_false, snapshots, load_snapshots)),
            bits: *bits,
        },
        LirExpression::Extract { arg, lsb, bits } => LirExpression::Extract {
            arg: Box::new(prepare_expression(arg, snapshots, load_snapshots)),
            lsb: *lsb,
            bits: *bits,
        },
        LirExpression::Concat { parts, bits } => LirExpression::Concat {
            parts: parts
                .iter()
                .map(|expression| prepare_expression(expression, snapshots, load_snapshots))
                .collect(),
            bits: *bits,
        },
        LirExpression::Undefined { bits } => LirExpression::Undefined { bits: *bits },
        LirExpression::Poison { bits } => LirExpression::Poison { bits: *bits },
        LirExpression::Intrinsic { name, args, bits } => LirExpression::Intrinsic {
            name: name.clone(),
            args: args
                .iter()
                .map(|expression| prepare_expression(expression, snapshots, load_snapshots))
                .collect(),
            bits: *bits,
        },
        LirExpression::Null { bits } => LirExpression::Null { bits: *bits },
        LirExpression::Allocate { kind, bits } => LirExpression::Allocate {
            kind: kind.clone(),
            bits: *bits,
        },
        LirExpression::ReadProperty {
            reference,
            name,
            bits,
        } => LirExpression::ReadProperty {
            reference: Box::new(prepare_expression(reference, snapshots, load_snapshots)),
            name: name.clone(),
            bits: *bits,
        },
        LirExpression::ReadElement {
            reference,
            index,
            bits,
        } => LirExpression::ReadElement {
            reference: Box::new(prepare_expression(reference, snapshots, load_snapshots)),
            index: Box::new(prepare_expression(index, snapshots, load_snapshots)),
            bits: *bits,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::prepare_instruction_semantics;
    use crate::ir::lir::{
        Lir, LirAddressSpace, LirEffect, LirExpression, LirLocation, LirOperationBinary, LirStatus,
        LirTerminator,
    };

    #[test]
    fn coerces_store_expression_to_destination_width() {
        let semantics = Lir {
            version: 1,
            status: LirStatus::Complete,
            metadata: Default::default(),
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![LirEffect::Store {
                space: LirAddressSpace::Default,
                addr: LirExpression::Const { value: 0, bits: 64 },
                expression: LirExpression::Read(Box::new(LirLocation::Register {
                    name: "wide".to_string(),
                    bits: 128,
                })),
                bits: 64,
            }],
            terminator: LirTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let prepared = prepare_instruction_semantics(&semantics).expect("prepare");
        match &prepared.effects[0] {
            LirEffect::Store { expression, .. } => match expression {
                LirExpression::Cast { bits, .. } => assert_eq!(*bits, 64),
                other => panic!("expected cast, got {:?}", other),
            },
            other => panic!("unexpected effect: {:?}", other),
        }
    }

    #[test]
    fn widens_shift_amount_to_operation_width() {
        let semantics = Lir {
            version: 1,
            status: LirStatus::Complete,
            metadata: Default::default(),
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "dst".to_string(),
                    bits: 32,
                },
                expression: LirExpression::Binary {
                    op: LirOperationBinary::LShr,
                    left: Box::new(LirExpression::Const { value: 7, bits: 32 }),
                    right: Box::new(LirExpression::Const { value: 3, bits: 5 }),
                    bits: 32,
                },
            }],
            terminator: LirTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let prepared = prepare_instruction_semantics(&semantics).expect("prepare");
        match &prepared.effects[0] {
            LirEffect::Set { expression, .. } => match expression {
                LirExpression::Binary { right, .. } => match right.as_ref() {
                    LirExpression::Cast { bits, .. } => assert_eq!(*bits, 32),
                    other => panic!("expected cast, got {:?}", other),
                },
                other => panic!("expected binary, got {:?}", other),
            },
            other => panic!("unexpected effect: {:?}", other),
        }
    }

    #[test]
    fn truncates_mismatched_binary_operand_to_expression_width() {
        let semantics = Lir {
            version: 1,
            status: LirStatus::Complete,
            metadata: Default::default(),
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "dst".to_string(),
                    bits: 32,
                },
                expression: LirExpression::Binary {
                    op: LirOperationBinary::Xor,
                    left: Box::new(LirExpression::Const { value: 7, bits: 32 }),
                    right: Box::new(LirExpression::Const { value: 1, bits: 64 }),
                    bits: 32,
                },
            }],
            terminator: LirTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let prepared = prepare_instruction_semantics(&semantics).expect("prepare");
        match &prepared.effects[0] {
            LirEffect::Set { expression, .. } => match expression {
                LirExpression::Binary { right, .. } => match right.as_ref() {
                    LirExpression::Cast { bits, .. } => assert_eq!(*bits, 32),
                    other => panic!("expected cast, got {:?}", other),
                },
                other => panic!("expected binary, got {:?}", other),
            },
            other => panic!("unexpected effect: {:?}", other),
        }
    }

    #[test]
    fn truncates_mismatched_compare_constant_to_operand_width() {
        let semantics = Lir {
            version: 1,
            status: LirStatus::Complete,
            metadata: Default::default(),
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![LirEffect::Set {
                dst: LirLocation::Flag {
                    name: "z".to_string(),
                    bits: 1,
                },
                expression: LirExpression::Compare {
                    op: crate::ir::lir::LirOperationCompare::Uge,
                    left: Box::new(LirExpression::Read(Box::new(LirLocation::Register {
                        name: "dst".to_string(),
                        bits: 32,
                    }))),
                    right: Box::new(LirExpression::Const {
                        value: 40,
                        bits: 64,
                    }),
                    bits: 1,
                },
            }],
            terminator: LirTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let prepared = prepare_instruction_semantics(&semantics).expect("prepare");
        match &prepared.effects[0] {
            LirEffect::Set { expression, .. } => match expression {
                LirExpression::Compare { right, .. } => match right.as_ref() {
                    LirExpression::Cast { bits, .. } => assert_eq!(*bits, 32),
                    other => panic!("expected cast, got {:?}", other),
                },
                other => panic!("expected compare, got {:?}", other),
            },
            other => panic!("unexpected effect: {:?}", other),
        }
    }
}
