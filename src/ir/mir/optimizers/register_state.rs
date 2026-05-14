// MIT License
//
// Copyright (c) [2025] [c3rb3ru5d3d53c]
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use crate::ir::mir::analysis::{MirRegisterAliases, incoming_register_aliases};
use crate::ir::mir::{Mir, MirOperation, MirOperationKind, MirTerminator, MirValue};
use std::collections::HashMap;

pub fn optimize_register_state(mir: &mut Mir) {
    let incoming = incoming_register_aliases(mir);

    for block in mir.blocks_mut() {
        let mut aliases = incoming.get(&block.name).cloned().unwrap_or_default();
        let mut normalized = Vec::with_capacity(block.operations.len());

        for mut operation in std::mem::take(&mut block.operations) {
            rewrite_operation(&mut operation, &aliases);

            if let MirOperationKind::Call { clobbers, .. } = &operation.kind {
                for clobber in clobbers {
                    aliases.insert(
                        clobber.register.clone(),
                        MirValue::undef(clobber.ty.clone()),
                    );
                }
            }

            if let Some((result, source)) = alias_from_operation(&operation) {
                aliases.insert(result, source);
                continue;
            }

            normalized.push(operation);
        }

        if let Some(terminator) = block.terminator.as_mut() {
            rewrite_terminator(terminator, &aliases);
        }

        block.operations = normalized;
    }
}

fn alias_from_operation(operation: &MirOperation) -> Option<(String, MirValue)> {
    let result = operation.result.clone()?;
    match &operation.kind {
        MirOperationKind::Intrinsic {
            name,
            arguments,
            result_types,
        } if name == "lir.set" && arguments.len() == 1 && result_types.len() == 1 => {
            Some((result, arguments[0].clone()))
        }
        MirOperationKind::Intrinsic {
            name, result_types, ..
        } if name.starts_with("mir.call_clobber.") && result_types.len() == 1 => {
            Some((result, MirValue::undef(result_types[0].clone())))
        }
        _ => None,
    }
}

fn rewrite_operation(operation: &mut MirOperation, aliases: &MirRegisterAliases) {
    match &mut operation.kind {
        MirOperationKind::Add { lhs, rhs, .. }
        | MirOperationKind::Sub { lhs, rhs, .. }
        | MirOperationKind::Mul { lhs, rhs, .. }
        | MirOperationKind::And { lhs, rhs, .. }
        | MirOperationKind::Or { lhs, rhs, .. }
        | MirOperationKind::Xor { lhs, rhs, .. }
        | MirOperationKind::Shl { lhs, rhs, .. }
        | MirOperationKind::LShr { lhs, rhs, .. }
        | MirOperationKind::AShr { lhs, rhs, .. }
        | MirOperationKind::Icmp { lhs, rhs, .. } => {
            rewrite_value(lhs, aliases);
            rewrite_value(rhs, aliases);
        }
        MirOperationKind::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            rewrite_value(condition, aliases);
            rewrite_value(when_true, aliases);
            rewrite_value(when_false, aliases);
        }
        MirOperationKind::Extract { value, .. }
        | MirOperationKind::Not { value, .. }
        | MirOperationKind::Popcount { value, .. } => rewrite_value(value, aliases),
        MirOperationKind::Load { address, .. } => {
            rewrite_value(address, aliases);
        }
        MirOperationKind::Store { address, value, .. } => {
            rewrite_value(address, aliases);
            rewrite_value(value, aliases);
        }
        MirOperationKind::Cast { value, .. } => {
            rewrite_value(value, aliases);
        }
        MirOperationKind::Call { arguments, .. }
        | MirOperationKind::Intrinsic { arguments, .. } => {
            for argument in arguments {
                rewrite_value(argument, aliases);
            }
        }
    }
}

fn rewrite_terminator(terminator: &mut MirTerminator, aliases: &MirRegisterAliases) {
    match terminator {
        MirTerminator::Jump { arguments, .. } => {
            for argument in arguments {
                rewrite_value(argument, aliases);
            }
        }
        MirTerminator::CondBr {
            condition,
            then_arguments,
            else_arguments,
            ..
        } => {
            rewrite_value(condition, aliases);
            for argument in then_arguments {
                rewrite_value(argument, aliases);
            }
            for argument in else_arguments {
                rewrite_value(argument, aliases);
            }
        }
        MirTerminator::Return { values } => {
            for value in values {
                rewrite_value(value, aliases);
            }
        }
        MirTerminator::Trap | MirTerminator::Unreachable => {}
    }
}

fn rewrite_value(value: &mut MirValue, aliases: &HashMap<String, MirValue>) {
    if let MirValue::Named { name, .. } = value {
        if let Some(replacement) = aliases.get(name) {
            *value = replacement.clone();
        }
    }
}
