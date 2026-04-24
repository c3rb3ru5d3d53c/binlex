use crate::lifters::llvm::abi::{coerce_expression_width, normalize_binary, normalize_compare};
use crate::semantics::{
    InstructionSemantics, SemanticEffect, SemanticExpression, SemanticLocation, SemanticTemporary,
    SemanticTerminator,
    normalize_instruction_semantics, validate_instruction_semantics,
};
use std::collections::{HashMap, HashSet};
use std::io::Error;

pub fn prepare_instruction_semantics(
    semantics: &InstructionSemantics,
) -> Result<InstructionSemantics, Error> {
    validate_instruction_semantics(semantics)?;
    let normalized = normalize_instruction_semantics(semantics);
    let (temporaries, snapshot_effects, effects, snapshots, load_snapshots) =
        snapshot_written_locations(&normalized);
    Ok(InstructionSemantics {
        version: normalized.version,
        status: normalized.status,
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
    semantics: &InstructionSemantics,
) -> (
    Vec<SemanticTemporary>,
    Vec<SemanticEffect>,
    Vec<SemanticEffect>,
    HashMap<SemanticLocation, SemanticLocation>,
    HashMap<SemanticExpression, SemanticLocation>,
) {
    let mut temporaries = semantics.temporaries.clone();
    let mut snapshots = HashMap::<SemanticLocation, SemanticLocation>::new();
    let mut load_snapshots = HashMap::<SemanticExpression, SemanticLocation>::new();
    let read_locations = collect_read_locations(semantics);
    let read_loads = collect_read_loads(semantics);
    let written_loads = collect_written_loads(semantics);
    let mut next_temp_id = temporaries.iter().map(|temp| temp.id).max().unwrap_or(0);
    let mut snapshot_effects = Vec::<SemanticEffect>::new();

    for effect in &semantics.effects {
        if let SemanticEffect::Set { dst, .. } = effect {
            let should_snapshot = matches!(
                dst,
                SemanticLocation::Register { .. }
                    | SemanticLocation::Flag { .. }
                    | SemanticLocation::ProgramCounter { .. }
            ) && read_locations.contains(dst);
            if should_snapshot && !snapshots.contains_key(dst) {
                next_temp_id += 1;
                let bits = match dst {
                    SemanticLocation::Register { bits, .. } => *bits,
                    SemanticLocation::Flag { bits, .. } => *bits,
                    SemanticLocation::ProgramCounter { bits } => *bits,
                    _ => 0,
                };
                let temp = SemanticLocation::Temporary {
                    id: next_temp_id,
                    bits,
                };
                temporaries.push(SemanticTemporary {
                    id: next_temp_id,
                    bits,
                    name: Some(format!("snapshot_{}", snapshots.len())),
                });
                snapshot_effects.push(SemanticEffect::Set {
                    dst: temp.clone(),
                    expression: SemanticExpression::Read(Box::new(dst.clone())),
                });
                snapshots.insert(dst.clone(), temp);
            }
        }
    }

    for load in read_loads {
        if written_loads.contains(&load) && !load_snapshots.contains_key(&load) {
            next_temp_id += 1;
            let bits = match &load {
                SemanticExpression::Load { bits, .. } => *bits,
                _ => continue,
            };
            let temp = SemanticLocation::Temporary {
                id: next_temp_id,
                bits,
            };
            temporaries.push(SemanticTemporary {
                id: next_temp_id,
                bits,
                name: Some(format!("load_snapshot_{}", load_snapshots.len())),
            });
            snapshot_effects.push(SemanticEffect::Set {
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

fn collect_read_locations(semantics: &InstructionSemantics) -> HashSet<SemanticLocation> {
    let mut reads = HashSet::new();
    for effect in &semantics.effects {
        collect_effect_reads(effect, &mut reads);
    }
    collect_terminator_reads(&semantics.terminator, &mut reads);
    reads
}

fn collect_read_loads(semantics: &InstructionSemantics) -> HashSet<SemanticExpression> {
    let mut reads = HashSet::new();
    for effect in &semantics.effects {
        collect_effect_loads(effect, &mut reads);
    }
    collect_terminator_loads(&semantics.terminator, &mut reads);
    reads
}

fn collect_written_loads(semantics: &InstructionSemantics) -> HashSet<SemanticExpression> {
    let mut writes = HashSet::new();
    for effect in &semantics.effects {
        match effect {
            SemanticEffect::Set { dst, .. } => {
                if let SemanticLocation::Memory { space, addr, bits } = dst {
                    writes.insert(SemanticExpression::Load {
                        space: space.clone(),
                        addr: addr.clone(),
                        bits: *bits,
                    });
                }
            }
            SemanticEffect::Store { space, addr, bits, .. } => {
                writes.insert(SemanticExpression::Load {
                    space: space.clone(),
                    addr: Box::new(addr.clone()),
                    bits: *bits,
                });
            }
            SemanticEffect::AtomicCmpXchg {
                space, addr, bits, ..
            } => {
                writes.insert(SemanticExpression::Load {
                    space: space.clone(),
                    addr: Box::new(addr.clone()),
                    bits: *bits,
                });
            }
            _ => {}
        }
    }
    writes
}

fn collect_effect_reads(effect: &SemanticEffect, reads: &mut HashSet<SemanticLocation>) {
    match effect {
        SemanticEffect::Set { expression, .. } => collect_expression_reads(expression, reads),
        SemanticEffect::Store {
            addr, expression, ..
        } => {
            collect_expression_reads(addr, reads);
            collect_expression_reads(expression, reads);
        }
        SemanticEffect::MemorySet {
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
        SemanticEffect::MemoryCopy {
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
        SemanticEffect::AtomicCmpXchg {
            addr,
            expected,
            desired,
            ..
        } => {
            collect_expression_reads(addr, reads);
            collect_expression_reads(expected, reads);
            collect_expression_reads(desired, reads);
        }
        SemanticEffect::Architecture { args, .. } | SemanticEffect::Intrinsic { args, .. } => {
            for arg in args {
                collect_expression_reads(arg, reads);
            }
        }
        SemanticEffect::Fence { .. }
        | SemanticEffect::Trap { .. }
        | SemanticEffect::Nop => {}
    }
}

fn collect_effect_loads(effect: &SemanticEffect, reads: &mut HashSet<SemanticExpression>) {
    match effect {
        SemanticEffect::Set { expression, .. } => collect_expression_loads(expression, reads),
        SemanticEffect::Store {
            addr, expression, ..
        } => {
            collect_expression_loads(addr, reads);
            collect_expression_loads(expression, reads);
        }
        SemanticEffect::MemorySet {
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
        SemanticEffect::MemoryCopy {
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
        SemanticEffect::AtomicCmpXchg {
            addr,
            expected,
            desired,
            ..
        } => {
            collect_expression_loads(addr, reads);
            collect_expression_loads(expected, reads);
            collect_expression_loads(desired, reads);
        }
        SemanticEffect::Architecture { args, .. } | SemanticEffect::Intrinsic { args, .. } => {
            for arg in args {
                collect_expression_loads(arg, reads);
            }
        }
        SemanticEffect::Fence { .. }
        | SemanticEffect::Trap { .. }
        | SemanticEffect::Nop => {}
    }
}

fn collect_terminator_reads(terminator: &SemanticTerminator, reads: &mut HashSet<SemanticLocation>) {
    match terminator {
        SemanticTerminator::Jump { target } => collect_expression_reads(target, reads),
        SemanticTerminator::Branch {
            condition,
            true_target,
            false_target,
        } => {
            collect_expression_reads(condition, reads);
            collect_expression_reads(true_target, reads);
            collect_expression_reads(false_target, reads);
        }
        SemanticTerminator::Call {
            target,
            return_target,
            ..
        } => {
            collect_expression_reads(target, reads);
            if let Some(return_target) = return_target {
                collect_expression_reads(return_target, reads);
            }
        }
        SemanticTerminator::Return { expression } => {
            if let Some(expression) = expression {
                collect_expression_reads(expression, reads);
            }
        }
        SemanticTerminator::FallThrough
        | SemanticTerminator::Unreachable
        | SemanticTerminator::Trap => {}
    }
}

fn collect_terminator_loads(
    terminator: &SemanticTerminator,
    reads: &mut HashSet<SemanticExpression>,
) {
    match terminator {
        SemanticTerminator::Jump { target } => collect_expression_loads(target, reads),
        SemanticTerminator::Branch {
            condition,
            true_target,
            false_target,
        } => {
            collect_expression_loads(condition, reads);
            collect_expression_loads(true_target, reads);
            collect_expression_loads(false_target, reads);
        }
        SemanticTerminator::Call {
            target,
            return_target,
            ..
        } => {
            collect_expression_loads(target, reads);
            if let Some(return_target) = return_target {
                collect_expression_loads(return_target, reads);
            }
        }
        SemanticTerminator::Return { expression } => {
            if let Some(expression) = expression {
                collect_expression_loads(expression, reads);
            }
        }
        SemanticTerminator::FallThrough
        | SemanticTerminator::Unreachable
        | SemanticTerminator::Trap => {}
    }
}

fn collect_expression_reads(expression: &SemanticExpression, reads: &mut HashSet<SemanticLocation>) {
    match expression {
        SemanticExpression::Read(location) => {
            reads.insert(location.as_ref().clone());
        }
        SemanticExpression::Load { addr, .. } => collect_expression_reads(addr, reads),
        SemanticExpression::Unary { arg, .. } => collect_expression_reads(arg, reads),
        SemanticExpression::Binary { left, right, .. } => {
            collect_expression_reads(left, reads);
            collect_expression_reads(right, reads);
        }
        SemanticExpression::Compare { left, right, .. } => {
            collect_expression_reads(left, reads);
            collect_expression_reads(right, reads);
        }
        SemanticExpression::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            collect_expression_reads(condition, reads);
            collect_expression_reads(when_true, reads);
            collect_expression_reads(when_false, reads);
        }
        SemanticExpression::Cast { arg, .. }
        | SemanticExpression::Extract { arg, .. } => collect_expression_reads(arg, reads),
        SemanticExpression::Concat { parts, .. } => {
            for part in parts {
                collect_expression_reads(part, reads);
            }
        }
        SemanticExpression::Intrinsic { args, .. }
        | SemanticExpression::Architecture { args, .. } => {
            for arg in args {
                collect_expression_reads(arg, reads);
            }
        }
        SemanticExpression::Const { .. }
        | SemanticExpression::Undefined { .. }
        | SemanticExpression::Poison { .. } => {}
    }
}

fn collect_expression_loads(expression: &SemanticExpression, reads: &mut HashSet<SemanticExpression>) {
    match expression {
        SemanticExpression::Read(_) => {}
        SemanticExpression::Load { space, addr, bits } => {
            reads.insert(SemanticExpression::Load {
                space: space.clone(),
                addr: Box::new((**addr).clone()),
                bits: *bits,
            });
            collect_expression_loads(addr, reads);
        }
        SemanticExpression::Unary { arg, .. }
        | SemanticExpression::Cast { arg, .. }
        | SemanticExpression::Extract { arg, .. } => collect_expression_loads(arg, reads),
        SemanticExpression::Binary { left, right, .. }
        | SemanticExpression::Compare { left, right, .. } => {
            collect_expression_loads(left, reads);
            collect_expression_loads(right, reads);
        }
        SemanticExpression::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            collect_expression_loads(condition, reads);
            collect_expression_loads(when_true, reads);
            collect_expression_loads(when_false, reads);
        }
        SemanticExpression::Concat { parts, .. } => {
            for part in parts {
                collect_expression_loads(part, reads);
            }
        }
        SemanticExpression::Intrinsic { args, .. }
        | SemanticExpression::Architecture { args, .. } => {
            for arg in args {
                collect_expression_loads(arg, reads);
            }
        }
        SemanticExpression::Const { .. }
        | SemanticExpression::Undefined { .. }
        | SemanticExpression::Poison { .. } => {}
    }
}

fn prepare_effect(
    effect: &SemanticEffect,
    snapshots: &HashMap<SemanticLocation, SemanticLocation>,
    load_snapshots: &HashMap<SemanticExpression, SemanticLocation>,
) -> SemanticEffect {
    match effect {
        SemanticEffect::Set { dst, expression } => match dst {
            crate::semantics::SemanticLocation::Memory { bits, .. } => SemanticEffect::Set {
                dst: dst.clone(),
                expression: prepare_expression(
                    &coerce_expression_width(expression.clone(), *bits),
                    snapshots,
                    load_snapshots,
                ),
            },
            _ => SemanticEffect::Set {
                dst: dst.clone(),
                expression: prepare_expression(expression, snapshots, load_snapshots),
            },
        },
        SemanticEffect::Store {
            space,
            addr,
            expression,
            bits,
        } => SemanticEffect::Store {
            space: space.clone(),
            addr: prepare_expression(addr, snapshots, load_snapshots),
            expression: prepare_expression(
                &coerce_expression_width(expression.clone(), *bits),
                snapshots,
                load_snapshots,
            ),
            bits: *bits,
        },
        SemanticEffect::MemorySet {
            space,
            addr,
            value,
            count,
            element_bits,
            decrement,
        } => SemanticEffect::MemorySet {
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
        SemanticEffect::MemoryCopy {
            src_space,
            src_addr,
            dst_space,
            dst_addr,
            count,
            element_bits,
            decrement,
        } => SemanticEffect::MemoryCopy {
            src_space: src_space.clone(),
            src_addr: prepare_expression(src_addr, snapshots, load_snapshots),
            dst_space: dst_space.clone(),
            dst_addr: prepare_expression(dst_addr, snapshots, load_snapshots),
            count: prepare_expression(count, snapshots, load_snapshots),
            element_bits: *element_bits,
            decrement: prepare_expression(decrement, snapshots, load_snapshots),
        },
        SemanticEffect::AtomicCmpXchg {
            space,
            addr,
            expected,
            desired,
            bits,
            observed,
        } => SemanticEffect::AtomicCmpXchg {
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
        SemanticEffect::Fence { kind } => SemanticEffect::Fence { kind: kind.clone() },
        SemanticEffect::Trap { kind } => SemanticEffect::Trap { kind: kind.clone() },
        SemanticEffect::Architecture {
            name,
            args,
            outputs,
        } => SemanticEffect::Architecture {
            name: name.clone(),
            args: args
                .iter()
                .map(|expression| prepare_expression(expression, snapshots, load_snapshots))
                .collect(),
            outputs: outputs.clone(),
        },
        SemanticEffect::Intrinsic {
            name,
            args,
            outputs,
        } => SemanticEffect::Intrinsic {
            name: name.clone(),
            args: args
                .iter()
                .map(|expression| prepare_expression(expression, snapshots, load_snapshots))
                .collect(),
            outputs: outputs.clone(),
        },
        SemanticEffect::Nop => SemanticEffect::Nop,
    }
}

fn prepare_terminator(
    terminator: &SemanticTerminator,
    snapshots: &HashMap<SemanticLocation, SemanticLocation>,
    load_snapshots: &HashMap<SemanticExpression, SemanticLocation>,
) -> SemanticTerminator {
    match terminator {
        SemanticTerminator::FallThrough => SemanticTerminator::FallThrough,
        SemanticTerminator::Jump { target } => SemanticTerminator::Jump {
            target: prepare_expression(target, snapshots, load_snapshots),
        },
        SemanticTerminator::Branch {
            condition,
            true_target,
            false_target,
        } => SemanticTerminator::Branch {
            condition: prepare_expression(condition, snapshots, load_snapshots),
            true_target: prepare_expression(true_target, snapshots, load_snapshots),
            false_target: prepare_expression(false_target, snapshots, load_snapshots),
        },
        SemanticTerminator::Call {
            target,
            return_target,
            does_return,
        } => SemanticTerminator::Call {
            target: prepare_expression(target, snapshots, load_snapshots),
            return_target: return_target
                .as_ref()
                .map(|expression| prepare_expression(expression, snapshots, load_snapshots)),
            does_return: *does_return,
        },
        SemanticTerminator::Return { expression } => SemanticTerminator::Return {
            expression: expression
                .as_ref()
                .map(|expression| prepare_expression(expression, snapshots, load_snapshots)),
        },
        SemanticTerminator::Unreachable => SemanticTerminator::Unreachable,
        SemanticTerminator::Trap => SemanticTerminator::Trap,
    }
}

fn prepare_expression(
    expression: &SemanticExpression,
    snapshots: &HashMap<SemanticLocation, SemanticLocation>,
    load_snapshots: &HashMap<SemanticExpression, SemanticLocation>,
) -> SemanticExpression {
    match expression {
        SemanticExpression::Const { value, bits } => SemanticExpression::Const {
            value: *value,
            bits: *bits,
        },
        SemanticExpression::Read(location) => SemanticExpression::Read(Box::new(
            snapshots
                .get(location.as_ref())
                .cloned()
                .unwrap_or_else(|| location.as_ref().clone()),
        )),
        SemanticExpression::Load { space, addr, bits } => {
            let prepared = SemanticExpression::Load {
                space: space.clone(),
                addr: Box::new(prepare_expression(addr, snapshots, load_snapshots)),
                bits: *bits,
            };
            if let Some(snapshot) = load_snapshots.get(&prepared) {
                SemanticExpression::Read(Box::new(snapshot.clone()))
            } else {
                prepared
            }
        }
        SemanticExpression::Unary { op, arg, bits } => SemanticExpression::Unary {
            op: *op,
            arg: Box::new(prepare_expression(arg, snapshots, load_snapshots)),
            bits: *bits,
        },
        SemanticExpression::Binary {
            op,
            left,
            right,
            bits,
        } => {
            let left = prepare_expression(left, snapshots, load_snapshots);
            let right = prepare_expression(right, snapshots, load_snapshots);
            let (left, right) = normalize_binary(*op, left, right, *bits);
            SemanticExpression::Binary {
                op: *op,
                left: Box::new(left),
                right: Box::new(right),
                bits: *bits,
            }
        }
        SemanticExpression::Cast { op, arg, bits } => SemanticExpression::Cast {
            op: *op,
            arg: Box::new(prepare_expression(arg, snapshots, load_snapshots)),
            bits: *bits,
        },
        SemanticExpression::Compare {
            op,
            left,
            right,
            bits,
        } => {
            let left = prepare_expression(left, snapshots, load_snapshots);
            let right = prepare_expression(right, snapshots, load_snapshots);
            let (left, right) = normalize_compare(left, right);
            SemanticExpression::Compare {
                op: *op,
                left: Box::new(left),
                right: Box::new(right),
                bits: *bits,
            }
        }
        SemanticExpression::Select {
            condition,
            when_true,
            when_false,
            bits,
        } => SemanticExpression::Select {
            condition: Box::new(prepare_expression(condition, snapshots, load_snapshots)),
            when_true: Box::new(prepare_expression(when_true, snapshots, load_snapshots)),
            when_false: Box::new(prepare_expression(when_false, snapshots, load_snapshots)),
            bits: *bits,
        },
        SemanticExpression::Extract { arg, lsb, bits } => SemanticExpression::Extract {
            arg: Box::new(prepare_expression(arg, snapshots, load_snapshots)),
            lsb: *lsb,
            bits: *bits,
        },
        SemanticExpression::Concat { parts, bits } => SemanticExpression::Concat {
            parts: parts
                .iter()
                .map(|expression| prepare_expression(expression, snapshots, load_snapshots))
                .collect(),
            bits: *bits,
        },
        SemanticExpression::Undefined { bits } => SemanticExpression::Undefined { bits: *bits },
        SemanticExpression::Poison { bits } => SemanticExpression::Poison { bits: *bits },
        SemanticExpression::Architecture { name, args, bits } => {
            SemanticExpression::Architecture {
                name: name.clone(),
                args: args
                    .iter()
                    .map(|expression| prepare_expression(expression, snapshots, load_snapshots))
                    .collect(),
                bits: *bits,
            }
        }
        SemanticExpression::Intrinsic { name, args, bits } => SemanticExpression::Intrinsic {
            name: name.clone(),
            args: args
                .iter()
                .map(|expression| prepare_expression(expression, snapshots, load_snapshots))
                .collect(),
            bits: *bits,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::prepare_instruction_semantics;
    use crate::semantics::{
        InstructionSemantics, SemanticAddressSpace, SemanticEffect, SemanticExpression,
        SemanticLocation, SemanticOperationBinary, SemanticStatus, SemanticTerminator,
    };

    #[test]
    fn coerces_store_expression_to_destination_width() {
        let semantics = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Store {
                space: SemanticAddressSpace::Default,
                addr: SemanticExpression::Const { value: 0, bits: 64 },
                expression: SemanticExpression::Read(Box::new(SemanticLocation::Register {
                    name: "wide".to_string(),
                    bits: 128,
                })),
                bits: 64,
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let prepared = prepare_instruction_semantics(&semantics).expect("prepare");
        match &prepared.effects[0] {
            SemanticEffect::Store { expression, .. } => match expression {
                SemanticExpression::Cast { bits, .. } => assert_eq!(*bits, 64),
                other => panic!("expected cast, got {:?}", other),
            },
            other => panic!("unexpected effect: {:?}", other),
        }
    }

    #[test]
    fn widens_shift_amount_to_operation_width() {
        let semantics = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "dst".to_string(),
                    bits: 32,
                },
                expression: SemanticExpression::Binary {
                    op: SemanticOperationBinary::LShr,
                    left: Box::new(SemanticExpression::Const { value: 7, bits: 32 }),
                    right: Box::new(SemanticExpression::Const { value: 3, bits: 5 }),
                    bits: 32,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let prepared = prepare_instruction_semantics(&semantics).expect("prepare");
        match &prepared.effects[0] {
            SemanticEffect::Set { expression, .. } => match expression {
                SemanticExpression::Binary { right, .. } => match right.as_ref() {
                    SemanticExpression::Cast { bits, .. } => assert_eq!(*bits, 32),
                    other => panic!("expected cast, got {:?}", other),
                },
                other => panic!("expected binary, got {:?}", other),
            },
            other => panic!("unexpected effect: {:?}", other),
        }
    }

    #[test]
    fn truncates_mismatched_binary_operand_to_expression_width() {
        let semantics = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "dst".to_string(),
                    bits: 32,
                },
                expression: SemanticExpression::Binary {
                    op: SemanticOperationBinary::Xor,
                    left: Box::new(SemanticExpression::Const { value: 7, bits: 32 }),
                    right: Box::new(SemanticExpression::Const { value: 1, bits: 64 }),
                    bits: 32,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let prepared = prepare_instruction_semantics(&semantics).expect("prepare");
        match &prepared.effects[0] {
            SemanticEffect::Set { expression, .. } => match expression {
                SemanticExpression::Binary { right, .. } => match right.as_ref() {
                    SemanticExpression::Cast { bits, .. } => assert_eq!(*bits, 32),
                    other => panic!("expected cast, got {:?}", other),
                },
                other => panic!("expected binary, got {:?}", other),
            },
            other => panic!("unexpected effect: {:?}", other),
        }
    }

    #[test]
    fn truncates_mismatched_compare_constant_to_operand_width() {
        let semantics = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Flag {
                    name: "z".to_string(),
                    bits: 1,
                },
                expression: SemanticExpression::Compare {
                    op: crate::semantics::SemanticOperationCompare::Uge,
                    left: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "dst".to_string(),
                            bits: 32,
                        },
                    ))),
                    right: Box::new(SemanticExpression::Const {
                        value: 40,
                        bits: 64,
                    }),
                    bits: 1,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let prepared = prepare_instruction_semantics(&semantics).expect("prepare");
        match &prepared.effects[0] {
            SemanticEffect::Set { expression, .. } => match expression {
                SemanticExpression::Compare { right, .. } => match right.as_ref() {
                    SemanticExpression::Cast { bits, .. } => assert_eq!(*bits, 32),
                    other => panic!("expected cast, got {:?}", other),
                },
                other => panic!("expected compare, got {:?}", other),
            },
            other => panic!("unexpected effect: {:?}", other),
        }
    }
}
