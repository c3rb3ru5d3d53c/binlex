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

use crate::ir::hir::block::HirBlock;
use crate::ir::hir::expression::HirExpression;
use crate::ir::hir::hir::{HirFunction, HirModule};
use crate::ir::hir::kind::{HirBinaryOperation, HirType, HirUnaryOperation};
use crate::ir::hir::place::HirPlace;
use crate::ir::hir::statement::{HirLocal, HirParameter, HirStatement};
use crate::ir::hir::target::HirTarget;
use crate::ir::hir::value::HirValue;
use crate::ir::mir::{
    MirBlock, MirControlTarget, MirFunction, MirModule, MirOperation, MirOperationKind,
    MirTerminator, MirValue,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Display, Formatter};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HirLowerError {
    message: String,
}

impl HirLowerError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl Display for HirLowerError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.message.fmt(f)
    }
}

impl std::error::Error for HirLowerError {}

pub fn lower_mir_function_to_hir(
    name: Option<String>,
    mir: &MirFunction,
) -> Result<HirFunction, HirLowerError> {
    let mut function = HirFunction::new(name.or_else(|| mir.name.clone()));
    function.abi = mir.abi.clone();
    function.parameters = mir
        .entry_parameters
        .iter()
        .enumerate()
        .map(|(index, parameter)| HirParameter {
            name: parameter
                .name
                .clone()
                .unwrap_or_else(|| format!("arg{index}")),
            ty: parameter.ty.clone(),
        })
        .collect();
    function.returns = infer_return_types(mir);
    function.locals = collect_locals(mir, &function.parameters);
    function.append_block(lower_function_body(mir)?);
    Ok(function)
}

pub fn lower_mir_module_to_hir(
    name: Option<String>,
    mir: &MirModule,
) -> Result<HirModule, HirLowerError> {
    let mut module = HirModule::new(name.or_else(|| mir.name.clone()));
    for function in &mir.functions {
        module.append_function(lower_mir_function_to_hir(function.name.clone(), function)?);
    }
    Ok(module)
}

pub fn lower_mir_block_to_hir(block: &MirBlock) -> Result<HirBlock, HirLowerError> {
    let context = LoweringContext::for_block(block);
    lower_plain_block(block, &context, false)
}

struct LoweringContext<'a> {
    blocks: BTreeMap<&'a str, &'a MirBlock>,
    incoming_direct_edges: BTreeMap<String, usize>,
}

impl<'a> LoweringContext<'a> {
    fn for_function(mir: &'a MirFunction) -> Self {
        let blocks = mir
            .blocks
            .iter()
            .map(|block| (block.name.as_str(), block))
            .collect::<BTreeMap<_, _>>();
        let mut incoming_direct_edges = BTreeMap::new();
        for block in &mir.blocks {
            if let Some(terminator) = &block.terminator {
                match terminator {
                    MirTerminator::Jump { target, .. } => {
                        if let MirControlTarget::Direct(name) = target {
                            *incoming_direct_edges.entry(name.clone()).or_insert(0) += 1;
                        }
                    }
                    MirTerminator::CondBr {
                        then_target,
                        else_target,
                        ..
                    } => {
                        if let MirControlTarget::Direct(name) = then_target {
                            *incoming_direct_edges.entry(name.clone()).or_insert(0) += 1;
                        }
                        if let MirControlTarget::Direct(name) = else_target {
                            *incoming_direct_edges.entry(name.clone()).or_insert(0) += 1;
                        }
                    }
                    _ => {}
                }
            }
        }
        Self {
            blocks,
            incoming_direct_edges,
        }
    }

    fn for_block(block: &'a MirBlock) -> Self {
        let mut blocks = BTreeMap::new();
        blocks.insert(block.name.as_str(), block);
        Self {
            blocks,
            incoming_direct_edges: BTreeMap::new(),
        }
    }

    fn block(&self, name: &str) -> Option<&'a MirBlock> {
        self.blocks.get(name).copied()
    }

    fn incoming_direct_edges(&self, name: &str) -> usize {
        self.incoming_direct_edges.get(name).copied().unwrap_or(0)
    }
}

fn lower_function_body(mir: &MirFunction) -> Result<HirBlock, HirLowerError> {
    let context = LoweringContext::for_function(mir);
    let mut body = HirBlock::new();
    let mut skipped = BTreeSet::<String>::new();
    let mut suppress_label = BTreeSet::<String>::new();

    for (index, block) in mir.blocks.iter().enumerate() {
        if skipped.contains(&block.name) {
            continue;
        }

        if index > 0 && !suppress_label.contains(&block.name) {
            body.append_statement(HirStatement::Label(block.name.clone()));
        }

        if let Some((statement, consumed, merge_label)) = try_lower_if(block, &context)? {
            lower_operations_into(&mut body, block)?;
            body.append_statement(statement);
            for label in consumed {
                skipped.insert(label);
            }
            if let Some(merge_label) = merge_label {
                suppress_label.insert(merge_label);
            }
            continue;
        }

        lower_block_into(&mut body, block, &context, false)?;
    }

    Ok(body)
}

fn try_lower_if(
    block: &MirBlock,
    context: &LoweringContext<'_>,
) -> Result<Option<(HirStatement, Vec<String>, Option<String>)>, HirLowerError> {
    let Some(MirTerminator::CondBr {
        condition,
        then_target,
        then_arguments,
        else_target,
        else_arguments,
    }) = &block.terminator
    else {
        return Ok(None);
    };

    let (MirControlTarget::Direct(then_name), MirControlTarget::Direct(else_name)) =
        (then_target, else_target)
    else {
        return Ok(None);
    };

    let (Some(then_block), Some(else_block)) = (context.block(then_name), context.block(else_name))
    else {
        return Ok(None);
    };

    let Some(then_kind) = branch_exit_kind(then_block) else {
        return Ok(None);
    };
    let Some(else_kind) = branch_exit_kind(else_block) else {
        return Ok(None);
    };

    let merge_label = match (&then_kind, &else_kind) {
        (BranchExitKind::Merge(then_merge), BranchExitKind::Merge(else_merge))
            if then_merge == else_merge =>
        {
            Some(then_merge.clone())
        }
        (BranchExitKind::Terminal, BranchExitKind::Terminal) => None,
        _ => return Ok(None),
    };

    let mut then_body = HirBlock::new();
    let mut else_body = HirBlock::new();
    if lower_branch_body(
        &mut then_body,
        then_block,
        then_arguments,
        merge_label.as_deref(),
        context,
    )
    .is_err()
    {
        return Ok(None);
    }
    if lower_branch_body(
        &mut else_body,
        else_block,
        else_arguments,
        merge_label.as_deref(),
        context,
    )
    .is_err()
    {
        return Ok(None);
    }

    let suppress_merge_label = merge_label
        .clone()
        .filter(|label| context.incoming_direct_edges(label) <= 2);

    Ok(Some((
        HirStatement::If {
            condition: lower_value_expression(condition),
            then_body,
            else_body: Some(else_body),
        },
        vec![then_name.clone(), else_name.clone()],
        suppress_merge_label,
    )))
}

enum BranchExitKind {
    Merge(String),
    Terminal,
}

fn branch_exit_kind(block: &MirBlock) -> Option<BranchExitKind> {
    match block.terminator.as_ref() {
        Some(MirTerminator::Jump { target, .. }) => match target {
            MirControlTarget::Direct(name) => Some(BranchExitKind::Merge(name.clone())),
            _ => None,
        },
        Some(MirTerminator::Return { .. } | MirTerminator::Trap | MirTerminator::Unreachable) => {
            Some(BranchExitKind::Terminal)
        }
        Some(_) | None => None,
    }
}

fn lower_branch_body(
    body: &mut HirBlock,
    block: &MirBlock,
    incoming_arguments: &[MirValue],
    merge_label: Option<&str>,
    context: &LoweringContext<'_>,
) -> Result<(), HirLowerError> {
    for statement in prepare_block_parameter_assignments(block, incoming_arguments) {
        body.append_statement(statement);
    }
    lower_operations_into(body, block)?;
    lower_branch_terminator(body, block, merge_label, context)
}

fn lower_branch_terminator(
    body: &mut HirBlock,
    block: &MirBlock,
    merge_label: Option<&str>,
    context: &LoweringContext<'_>,
) -> Result<(), HirLowerError> {
    match block.terminator.as_ref() {
        Some(MirTerminator::Jump { target, arguments }) => {
            let HirTarget::Direct(name) = lower_target(target) else {
                return Err(HirLowerError::new(
                    "structured branch recovery requires direct merge targets",
                ));
            };
            if Some(name.as_str()) == merge_label {
                if let Some(merge_block) = context.block(&name) {
                    for statement in prepare_block_parameter_assignments(merge_block, arguments) {
                        body.append_statement(statement);
                    }
                }
                Ok(())
            } else {
                lower_terminator_into(body, block, context)
            }
        }
        Some(_) => lower_terminator_into(body, block, context),
        None => Err(HirLowerError::new("mir block is missing a terminator")),
    }
}

fn lower_block_into(
    body: &mut HirBlock,
    block: &MirBlock,
    context: &LoweringContext<'_>,
    include_label: bool,
) -> Result<(), HirLowerError> {
    if include_label {
        body.append_statement(HirStatement::Label(block.name.clone()));
    }
    lower_operations_into(body, block)?;
    lower_terminator_into(body, block, context)
}

fn lower_plain_block(
    block: &MirBlock,
    context: &LoweringContext<'_>,
    include_label: bool,
) -> Result<HirBlock, HirLowerError> {
    let mut lowered = HirBlock::new();
    lower_block_into(&mut lowered, block, context, include_label)?;
    Ok(lowered)
}

fn lower_operations_into(body: &mut HirBlock, block: &MirBlock) -> Result<(), HirLowerError> {
    for operation in &block.operations {
        body.append_statement(lower_operation(operation)?);
    }
    Ok(())
}

fn lower_terminator_into(
    body: &mut HirBlock,
    block: &MirBlock,
    context: &LoweringContext<'_>,
) -> Result<(), HirLowerError> {
    match block.terminator.as_ref() {
        Some(MirTerminator::Jump { target, arguments }) => {
            if let MirControlTarget::Direct(name) = target {
                if let Some(target_block) = context.block(name) {
                    for statement in prepare_block_parameter_assignments(target_block, arguments) {
                        body.append_statement(statement);
                    }
                }
            }
            body.append_statement(HirStatement::Goto(lower_target(target)));
        }
        Some(MirTerminator::CondBr {
            condition,
            then_target,
            then_arguments,
            else_target,
            else_arguments,
        }) => {
            let mut then_body = HirBlock::new();
            let mut else_body = HirBlock::new();

            if let MirControlTarget::Direct(name) = then_target {
                if let Some(target_block) = context.block(name) {
                    for statement in
                        prepare_block_parameter_assignments(target_block, then_arguments)
                    {
                        then_body.append_statement(statement);
                    }
                }
            }
            then_body.append_statement(HirStatement::Goto(lower_target(then_target)));

            if let MirControlTarget::Direct(name) = else_target {
                if let Some(target_block) = context.block(name) {
                    for statement in
                        prepare_block_parameter_assignments(target_block, else_arguments)
                    {
                        else_body.append_statement(statement);
                    }
                }
            }
            else_body.append_statement(HirStatement::Goto(lower_target(else_target)));

            body.append_statement(HirStatement::If {
                condition: lower_value_expression(condition),
                then_body,
                else_body: Some(else_body),
            });
        }
        Some(MirTerminator::Return { values }) => {
            body.append_statement(HirStatement::Return {
                values: values.iter().map(lower_value_expression).collect(),
            });
        }
        Some(MirTerminator::Trap) => body.append_statement(HirStatement::Trap),
        Some(MirTerminator::Unreachable) => body.append_statement(HirStatement::Unreachable),
        None => return Err(HirLowerError::new("mir block is missing a terminator")),
    }
    Ok(())
}

fn lower_operation(operation: &MirOperation) -> Result<HirStatement, HirLowerError> {
    match &operation.kind {
        MirOperationKind::Copy { value, .. } => {
            lower_assign(operation, lower_value_expression(value))
        }
        MirOperationKind::Add { lhs, rhs, ty } => lower_assign(
            operation,
            binary(HirBinaryOperation::Add, lhs, rhs, ty.clone()),
        ),
        MirOperationKind::Sub { lhs, rhs, ty } => lower_assign(
            operation,
            binary(HirBinaryOperation::Sub, lhs, rhs, ty.clone()),
        ),
        MirOperationKind::Mul { lhs, rhs, ty } => lower_assign(
            operation,
            binary(HirBinaryOperation::Mul, lhs, rhs, ty.clone()),
        ),
        MirOperationKind::FAdd { lhs, rhs, ty } => lower_assign(
            operation,
            binary(HirBinaryOperation::FAdd, lhs, rhs, ty.clone()),
        ),
        MirOperationKind::FSub { lhs, rhs, ty } => lower_assign(
            operation,
            binary(HirBinaryOperation::FSub, lhs, rhs, ty.clone()),
        ),
        MirOperationKind::FMul { lhs, rhs, ty } => lower_assign(
            operation,
            binary(HirBinaryOperation::FMul, lhs, rhs, ty.clone()),
        ),
        MirOperationKind::FDiv { lhs, rhs, ty } => lower_assign(
            operation,
            binary(HirBinaryOperation::FDiv, lhs, rhs, ty.clone()),
        ),
        MirOperationKind::And { lhs, rhs, ty } => lower_assign(
            operation,
            binary(HirBinaryOperation::And, lhs, rhs, ty.clone()),
        ),
        MirOperationKind::Or { lhs, rhs, ty } => lower_assign(
            operation,
            binary(HirBinaryOperation::Or, lhs, rhs, ty.clone()),
        ),
        MirOperationKind::Xor { lhs, rhs, ty } => lower_assign(
            operation,
            binary(HirBinaryOperation::Xor, lhs, rhs, ty.clone()),
        ),
        MirOperationKind::Shl { lhs, rhs, ty } => lower_assign(
            operation,
            binary(HirBinaryOperation::Shl, lhs, rhs, ty.clone()),
        ),
        MirOperationKind::LShr { lhs, rhs, ty } => lower_assign(
            operation,
            binary(HirBinaryOperation::LShr, lhs, rhs, ty.clone()),
        ),
        MirOperationKind::AShr { lhs, rhs, ty } => lower_assign(
            operation,
            binary(HirBinaryOperation::AShr, lhs, rhs, ty.clone()),
        ),
        MirOperationKind::UDiv { lhs, rhs, ty } => lower_assign(
            operation,
            binary(HirBinaryOperation::UDiv, lhs, rhs, ty.clone()),
        ),
        MirOperationKind::SDiv { lhs, rhs, ty } => lower_assign(
            operation,
            binary(HirBinaryOperation::SDiv, lhs, rhs, ty.clone()),
        ),
        MirOperationKind::URem { lhs, rhs, ty } => lower_assign(
            operation,
            binary(HirBinaryOperation::URem, lhs, rhs, ty.clone()),
        ),
        MirOperationKind::SRem { lhs, rhs, ty } => lower_assign(
            operation,
            binary(HirBinaryOperation::SRem, lhs, rhs, ty.clone()),
        ),
        MirOperationKind::RotateLeft { lhs, rhs, ty } => lower_assign(
            operation,
            binary(HirBinaryOperation::RotateLeft, lhs, rhs, ty.clone()),
        ),
        MirOperationKind::RotateRight { lhs, rhs, ty } => lower_assign(
            operation,
            binary(HirBinaryOperation::RotateRight, lhs, rhs, ty.clone()),
        ),
        MirOperationKind::Select {
            condition,
            when_true,
            when_false,
            ty,
        } => lower_assign(
            operation,
            HirExpression::Select {
                condition: Box::new(lower_value_expression(condition)),
                when_true: Box::new(lower_value_expression(when_true)),
                when_false: Box::new(lower_value_expression(when_false)),
                ty: ty.clone(),
            },
        ),
        MirOperationKind::Concat { parts, ty } => lower_assign(
            operation,
            HirExpression::Concat {
                parts: parts.iter().map(lower_value_expression).collect(),
                ty: ty.clone(),
            },
        ),
        MirOperationKind::Extract { value, lsb, ty } => lower_assign(
            operation,
            HirExpression::Extract {
                value: Box::new(lower_value_expression(value)),
                lsb: *lsb,
                ty: ty.clone(),
            },
        ),
        MirOperationKind::Not { value, ty } => lower_assign(
            operation,
            unary(HirUnaryOperation::BitNot, value, ty.clone()),
        ),
        MirOperationKind::Neg { value, ty } => {
            lower_assign(operation, unary(HirUnaryOperation::Neg, value, ty.clone()))
        }
        MirOperationKind::Popcount { value, ty } => lower_assign(
            operation,
            unary(HirUnaryOperation::Popcount, value, ty.clone()),
        ),
        MirOperationKind::CountLeadingZeros { value, ty } => lower_assign(
            operation,
            unary(HirUnaryOperation::CountLeadingZeros, value, ty.clone()),
        ),
        MirOperationKind::CountTrailingZeros { value, ty } => lower_assign(
            operation,
            unary(HirUnaryOperation::CountTrailingZeros, value, ty.clone()),
        ),
        MirOperationKind::Load {
            address_space,
            address,
            ty,
        } => lower_assign(
            operation,
            HirExpression::Load {
                address_space: address_space.clone(),
                address: Box::new(lower_value_expression(address)),
                ty: ty.clone(),
            },
        ),
        MirOperationKind::Store {
            address_space,
            address,
            value,
            ty,
        } => Ok(HirStatement::Assign {
            target: HirPlace::Memory {
                address_space: address_space.clone(),
                address: Box::new(lower_value_expression(address)),
                ty: ty.clone(),
            },
            value: lower_value_expression(value),
        }),
        MirOperationKind::MemoryCopy {
            src_space,
            src_address,
            dst_space,
            dst_address,
            count,
            ..
        } => Ok(HirStatement::Expr(HirExpression::Intrinsic {
            name: "memcpy".to_string(),
            arguments: vec![
                HirExpression::Load {
                    address_space: src_space.clone(),
                    address: Box::new(lower_value_expression(src_address)),
                    ty: HirType::memory(),
                },
                HirExpression::Load {
                    address_space: dst_space.clone(),
                    address: Box::new(lower_value_expression(dst_address)),
                    ty: HirType::memory(),
                },
                lower_value_expression(count),
            ],
            return_types: Vec::new(),
        })),
        MirOperationKind::Icmp { op, lhs, rhs, ty } => lower_assign(
            operation,
            HirExpression::Compare {
                op: *op,
                lhs: Box::new(lower_value_expression(lhs)),
                rhs: Box::new(lower_value_expression(rhs)),
                ty: ty.clone(),
            },
        ),
        MirOperationKind::Fcmp { op, lhs, rhs, ty } => lower_assign(
            operation,
            HirExpression::FloatCompare {
                op: *op,
                lhs: Box::new(lower_value_expression(lhs)),
                rhs: Box::new(lower_value_expression(rhs)),
                ty: ty.clone(),
            },
        ),
        MirOperationKind::Cast { op, value, ty } => lower_assign(
            operation,
            HirExpression::Cast {
                op: *op,
                value: Box::new(lower_value_expression(value)),
                ty: ty.clone(),
            },
        ),
        MirOperationKind::Call {
            target,
            arguments,
            result_types,
            ..
        } => lower_assign(
            operation,
            HirExpression::Call {
                target: lower_target(target),
                arguments: arguments.iter().map(lower_value_expression).collect(),
                return_types: result_types.clone(),
            },
        ),
        MirOperationKind::Intrinsic {
            name,
            arguments,
            result_types,
        } => lower_assign(
            operation,
            HirExpression::Intrinsic {
                name: name.clone(),
                arguments: arguments.iter().map(lower_value_expression).collect(),
                return_types: result_types.clone(),
            },
        ),
    }
}

fn lower_assign(
    operation: &MirOperation,
    value: HirExpression,
) -> Result<HirStatement, HirLowerError> {
    match &operation.result {
        Some(result) => Ok(HirStatement::Assign {
            target: HirPlace::Named {
                name: result.clone(),
                ty: result_type(operation)
                    .ok_or_else(|| HirLowerError::new("missing hir assignment type"))?,
            },
            value,
        }),
        None => Ok(HirStatement::Expr(value)),
    }
}

fn lower_value_expression(value: &MirValue) -> HirExpression {
    HirExpression::value(HirValue::from_mir(value))
}

fn lower_target(target: &MirControlTarget) -> HirTarget {
    HirTarget::from_mir(target)
}

fn unary(op: HirUnaryOperation, value: &MirValue, ty: HirType) -> HirExpression {
    HirExpression::Unary {
        op,
        value: Box::new(lower_value_expression(value)),
        ty,
    }
}

fn binary(op: HirBinaryOperation, lhs: &MirValue, rhs: &MirValue, ty: HirType) -> HirExpression {
    HirExpression::Binary {
        op,
        lhs: Box::new(lower_value_expression(lhs)),
        rhs: Box::new(lower_value_expression(rhs)),
        ty,
    }
}

fn collect_locals(mir: &MirFunction, parameters: &[HirParameter]) -> Vec<HirLocal> {
    let parameter_names = parameters
        .iter()
        .map(|parameter| parameter.name.clone())
        .collect::<BTreeSet<_>>();
    let mut locals = BTreeMap::<String, HirType>::new();

    for block in &mir.blocks {
        for parameter in &block.parameters {
            if let Some(name) = &parameter.name {
                if !parameter_names.contains(name) {
                    locals
                        .entry(name.clone())
                        .or_insert_with(|| parameter.ty.clone());
                }
            }
        }
        for operation in &block.operations {
            if let Some(result) = &operation.result {
                if !parameter_names.contains(result) {
                    if let Some(ty) = result_type(operation) {
                        locals.entry(result.clone()).or_insert(ty);
                    }
                }
            }
            collect_named_values_from_operation(operation, &mut locals, &parameter_names);
        }
        if let Some(MirTerminator::Return { values }) = &block.terminator {
            for value in values {
                collect_named_value(value, &mut locals, &parameter_names);
            }
        }
    }

    locals
        .into_iter()
        .map(|(name, ty)| HirLocal {
            name,
            ty,
            init: None,
        })
        .collect()
}

fn collect_named_values_from_operation(
    operation: &MirOperation,
    locals: &mut BTreeMap<String, HirType>,
    parameter_names: &BTreeSet<String>,
) {
    match &operation.kind {
        MirOperationKind::Copy { value, .. }
        | MirOperationKind::Not { value, .. }
        | MirOperationKind::Neg { value, .. }
        | MirOperationKind::Popcount { value, .. }
        | MirOperationKind::CountLeadingZeros { value, .. }
        | MirOperationKind::CountTrailingZeros { value, .. }
        | MirOperationKind::Cast { value, .. }
        | MirOperationKind::Extract { value, .. } => {
            collect_named_value(value, locals, parameter_names)
        }
        MirOperationKind::Add { lhs, rhs, .. }
        | MirOperationKind::Sub { lhs, rhs, .. }
        | MirOperationKind::Mul { lhs, rhs, .. }
        | MirOperationKind::FAdd { lhs, rhs, .. }
        | MirOperationKind::FSub { lhs, rhs, .. }
        | MirOperationKind::FMul { lhs, rhs, .. }
        | MirOperationKind::FDiv { lhs, rhs, .. }
        | MirOperationKind::And { lhs, rhs, .. }
        | MirOperationKind::Or { lhs, rhs, .. }
        | MirOperationKind::Xor { lhs, rhs, .. }
        | MirOperationKind::Shl { lhs, rhs, .. }
        | MirOperationKind::LShr { lhs, rhs, .. }
        | MirOperationKind::AShr { lhs, rhs, .. }
        | MirOperationKind::UDiv { lhs, rhs, .. }
        | MirOperationKind::SDiv { lhs, rhs, .. }
        | MirOperationKind::URem { lhs, rhs, .. }
        | MirOperationKind::SRem { lhs, rhs, .. }
        | MirOperationKind::RotateLeft { lhs, rhs, .. }
        | MirOperationKind::RotateRight { lhs, rhs, .. }
        | MirOperationKind::Icmp { lhs, rhs, .. }
        | MirOperationKind::Fcmp { lhs, rhs, .. } => {
            collect_named_value(lhs, locals, parameter_names);
            collect_named_value(rhs, locals, parameter_names);
        }
        MirOperationKind::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            collect_named_value(condition, locals, parameter_names);
            collect_named_value(when_true, locals, parameter_names);
            collect_named_value(when_false, locals, parameter_names);
        }
        MirOperationKind::Concat { parts, .. } => {
            for part in parts {
                collect_named_value(part, locals, parameter_names);
            }
        }
        MirOperationKind::Load { address, .. } => {
            collect_named_value(address, locals, parameter_names)
        }
        MirOperationKind::Store { address, value, .. } => {
            collect_named_value(address, locals, parameter_names);
            collect_named_value(value, locals, parameter_names);
        }
        MirOperationKind::MemoryCopy {
            src_address,
            dst_address,
            count,
            decrement,
            ..
        } => {
            collect_named_value(src_address, locals, parameter_names);
            collect_named_value(dst_address, locals, parameter_names);
            collect_named_value(count, locals, parameter_names);
            collect_named_value(decrement, locals, parameter_names);
        }
        MirOperationKind::Call { arguments, .. }
        | MirOperationKind::Intrinsic { arguments, .. } => {
            for argument in arguments {
                collect_named_value(argument, locals, parameter_names);
            }
        }
    }
}

fn collect_named_value(
    value: &MirValue,
    locals: &mut BTreeMap<String, HirType>,
    parameter_names: &BTreeSet<String>,
) {
    if let MirValue::Named { name, ty } = value {
        if !parameter_names.contains(name) {
            locals.entry(name.clone()).or_insert_with(|| ty.clone());
        }
    }
}

fn result_type(operation: &MirOperation) -> Option<HirType> {
    match &operation.kind {
        MirOperationKind::Copy { ty, .. }
        | MirOperationKind::Add { ty, .. }
        | MirOperationKind::Sub { ty, .. }
        | MirOperationKind::Mul { ty, .. }
        | MirOperationKind::FAdd { ty, .. }
        | MirOperationKind::FSub { ty, .. }
        | MirOperationKind::FMul { ty, .. }
        | MirOperationKind::FDiv { ty, .. }
        | MirOperationKind::And { ty, .. }
        | MirOperationKind::Or { ty, .. }
        | MirOperationKind::Xor { ty, .. }
        | MirOperationKind::Shl { ty, .. }
        | MirOperationKind::LShr { ty, .. }
        | MirOperationKind::AShr { ty, .. }
        | MirOperationKind::UDiv { ty, .. }
        | MirOperationKind::SDiv { ty, .. }
        | MirOperationKind::URem { ty, .. }
        | MirOperationKind::SRem { ty, .. }
        | MirOperationKind::RotateLeft { ty, .. }
        | MirOperationKind::RotateRight { ty, .. }
        | MirOperationKind::Select { ty, .. }
        | MirOperationKind::Extract { ty, .. }
        | MirOperationKind::Load { ty, .. }
        | MirOperationKind::Icmp { ty, .. }
        | MirOperationKind::Fcmp { ty, .. }
        | MirOperationKind::Cast { ty, .. }
        | MirOperationKind::Not { ty, .. }
        | MirOperationKind::Neg { ty, .. }
        | MirOperationKind::Popcount { ty, .. }
        | MirOperationKind::CountLeadingZeros { ty, .. }
        | MirOperationKind::CountTrailingZeros { ty, .. }
        | MirOperationKind::Concat { ty, .. } => Some(ty.clone()),
        MirOperationKind::Call { result_types, .. }
        | MirOperationKind::Intrinsic { result_types, .. } => result_types.first().cloned(),
        MirOperationKind::Store { .. } | MirOperationKind::MemoryCopy { .. } => None,
    }
}

fn infer_return_types(mir: &MirFunction) -> Vec<HirType> {
    for block in &mir.blocks {
        if let Some(MirTerminator::Return { values }) = &block.terminator {
            return values
                .iter()
                .map(|value| HirValue::from_mir(value).ty())
                .collect();
        }
    }
    Vec::new()
}

fn prepare_block_parameter_assignments(
    block: &MirBlock,
    arguments: &[MirValue],
) -> Vec<HirStatement> {
    block
        .parameters
        .iter()
        .zip(arguments.iter())
        .filter_map(|(parameter, argument)| {
            let name = parameter.name.clone()?;
            Some(HirStatement::Assign {
                target: HirPlace::Named {
                    name,
                    ty: parameter.ty.clone(),
                },
                value: lower_value_expression(argument),
            })
        })
        .collect()
}
