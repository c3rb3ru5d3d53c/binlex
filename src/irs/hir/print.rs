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

#![allow(dead_code)]

use super::block::HirBlock;
use super::expression::HirExpression;
use super::hir::{HirFunction, HirModule};
use super::kind::{
    HirBinaryOperation, HirCastOperation, HirCompareOperation, HirFloatCompareOperation, HirType,
    HirUnaryOperation,
};
use super::place::HirPlace;
use super::statement::{HirLocal, HirParameter, HirStatement, HirSwitchCase};
use super::target::HirTarget;
use super::value::HirValue;
use std::collections::{BTreeMap, BTreeSet};

pub fn format_hir_function(hir: &HirFunction) -> String {
    let context = crate::irs::mlir::context();
    hir_function_operation(&context, hir)
        .and_then(|op| op.to_string())
        .unwrap_or_else(|error| format!("// mlir print failed: {error}"))
}

pub fn format_hir_module(module: &HirModule) -> String {
    let context = crate::irs::mlir::context();
    hir_module_operation(&context, module)
        .and_then(|op| crate::irs::mlir::MlirDocument::from_context_and_ops(context, vec![op]))
        .and_then(|document| document.text())
        .unwrap_or_else(|error| format!("// mlir print failed: {error}"))
}

fn hir_local_operation(context: &mlir::Context, local: &HirLocal) -> mlir::Result<mlir::Operation> {
    crate::irs::mlir::operation(
        context,
        "binlex.hir.local",
        hir_local_attrs(context, local),
        Vec::new(),
    )
}

fn hir_local_attrs(context: &mlir::Context, local: &HirLocal) -> Vec<mlir::NamedAttribute> {
    let mut attrs = vec![
        crate::irs::mlir::string_attr(context, "name", &local.name),
        crate::irs::mlir::string_attr(context, "ty", &format_type(&local.ty)),
    ];
    if let Some(init) = &local.init {
        attrs.push(crate::irs::mlir::string_attr(
            context,
            "init",
            &format_expression(init),
        ));
    }
    if let Some(storage) = &local.storage {
        attrs.push(crate::irs::mlir::string_attr(
            context,
            "storage",
            &format!("{storage:?}"),
        ));
    }
    attrs
}

fn hir_statement_operation(
    context: &mlir::Context,
    statement: &HirStatement,
) -> mlir::Result<mlir::Operation> {
    let (name, attrs, regions) = hir_statement_parts(context, statement)?;
    crate::irs::mlir::operation(context, name, attrs, regions)
}

fn hir_statement_parts(
    context: &mlir::Context,
    statement: &HirStatement,
) -> mlir::Result<(&'static str, Vec<mlir::NamedAttribute>, Vec<mlir::Region>)> {
    Ok(match statement {
        HirStatement::Assign { target, value } => (
            "binlex.hir.assign",
            vec![
                crate::irs::mlir::string_attr(context, "target", &format_place(target)),
                crate::irs::mlir::string_attr(context, "value", &format_expression(value)),
            ],
            Vec::new(),
        ),
        HirStatement::Expr(expression) => (
            "binlex.hir.expr",
            vec![crate::irs::mlir::string_attr(
                context,
                "value",
                &format_expression(expression),
            )],
            Vec::new(),
        ),
        HirStatement::If {
            condition,
            then_body,
            else_body,
        } => {
            let mut regions = vec![hir_block_region(context, then_body)?];
            if let Some(else_body) = else_body {
                regions.push(hir_block_region(context, else_body)?);
            }
            (
                "binlex.hir.if",
                vec![crate::irs::mlir::string_attr(
                    context,
                    "condition",
                    &format_expression(condition),
                )],
                regions,
            )
        }
        HirStatement::While { condition, body } => (
            "binlex.hir.while",
            vec![crate::irs::mlir::string_attr(
                context,
                "condition",
                &format_expression(condition),
            )],
            vec![hir_block_region(context, body)?],
        ),
        HirStatement::Loop { body } => (
            "binlex.hir.loop",
            Vec::new(),
            vec![hir_block_region(context, body)?],
        ),
        HirStatement::Switch {
            value,
            cases,
            default,
        } => {
            let mut regions = cases
                .iter()
                .map(|case| hir_switch_case_region(context, case))
                .collect::<mlir::Result<Vec<_>>>()?;
            if let Some(default) = default {
                regions.push(hir_block_region(context, default)?);
            }
            (
                "binlex.hir.switch",
                vec![crate::irs::mlir::string_attr(
                    context,
                    "value",
                    &format_expression(value),
                )],
                regions,
            )
        }
        HirStatement::Break => ("binlex.hir.break", Vec::new(), Vec::new()),
        HirStatement::Continue => ("binlex.hir.continue", Vec::new(), Vec::new()),
        HirStatement::Return { values } => (
            "binlex.hir.return",
            vec![crate::irs::mlir::string_attr(
                context,
                "values",
                &values
                    .iter()
                    .map(format_expression)
                    .collect::<Vec<_>>()
                    .join("\n"),
            )],
            Vec::new(),
        ),
        HirStatement::Label(label) => (
            "binlex.hir.label",
            vec![crate::irs::mlir::string_attr(context, "target", label)],
            Vec::new(),
        ),
        HirStatement::Goto(target) => (
            "binlex.hir.goto",
            vec![crate::irs::mlir::string_attr(
                context,
                "target",
                &format_target(target),
            )],
            Vec::new(),
        ),
        HirStatement::Trap => ("binlex.hir.trap", Vec::new(), Vec::new()),
        HirStatement::Unreachable => ("binlex.hir.unreachable", Vec::new(), Vec::new()),
    })
}

fn hir_switch_case_region(
    context: &mlir::Context,
    case: &HirSwitchCase,
) -> mlir::Result<mlir::Region> {
    let mut ops = vec![crate::irs::mlir::operation(
        context,
        "binlex.hir.case",
        vec![crate::irs::mlir::string_attr(
            context,
            "value",
            &format_value(&case.value),
        )],
        Vec::new(),
    )?];
    ops.extend(hir_block_operations(context, &case.body)?);
    Ok(crate::irs::mlir::region_with_ops(ops))
}

fn hir_block_operation(
    context: &mlir::Context,
    index: usize,
    block: &HirBlock,
) -> mlir::Result<mlir::Operation> {
    crate::irs::mlir::operation(
        context,
        "binlex.hir.block",
        vec![crate::irs::mlir::string_attr(
            context,
            "sym_name",
            &format!("block{index}"),
        )],
        vec![hir_block_region(context, block)?],
    )
}

fn hir_block_region(context: &mlir::Context, block: &HirBlock) -> mlir::Result<mlir::Region> {
    Ok(crate::irs::mlir::region_with_ops(hir_block_operations(
        context, block,
    )?))
}

fn hir_block_operations(
    context: &mlir::Context,
    block: &HirBlock,
) -> mlir::Result<Vec<mlir::Operation>> {
    block
        .statements
        .iter()
        .map(|statement| hir_statement_operation(context, statement))
        .collect()
}

fn hir_function_operation(
    context: &mlir::Context,
    hir: &HirFunction,
) -> mlir::Result<mlir::Operation> {
    let name = hir.name.clone().unwrap_or_else(|| "anonymous".to_string());
    let mut attrs = vec![
        crate::irs::mlir::string_attr(context, "sym_name", &name),
        crate::irs::mlir::string_attr(
            context,
            "parameters",
            &hir.parameters
                .iter()
                .map(format_parameter)
                .collect::<Vec<_>>()
                .join("\n"),
        ),
        crate::irs::mlir::string_attr(context, "returns", &format_return_types(&hir.returns)),
    ];
    if !hir.locals.is_empty() {
        attrs.push(crate::irs::mlir::string_attr(
            context,
            "locals",
            &hir.locals
                .iter()
                .map(format_local)
                .collect::<Vec<_>>()
                .join("\n"),
        ));
    }

    let explicit_locals = hir
        .locals
        .iter()
        .filter(|local| local.init.is_some() || !is_generated_temp_name(&local.name))
        .cloned()
        .collect::<Vec<_>>();
    let mut ops = explicit_locals
        .iter()
        .map(|local| hir_local_operation(context, local))
        .collect::<mlir::Result<Vec<_>>>()?;
    for (index, block) in hir.blocks.iter().enumerate() {
        ops.push(hir_block_operation(context, index, block)?);
    }

    crate::irs::mlir::operation(
        context,
        "binlex.hir.function",
        attrs,
        vec![crate::irs::mlir::region_with_ops(ops)],
    )
}

pub(crate) fn hir_module_operation(
    context: &mlir::Context,
    module: &HirModule,
) -> mlir::Result<mlir::Operation> {
    let name = module
        .name
        .clone()
        .unwrap_or_else(|| "anonymous".to_string());
    let ops = module
        .functions
        .iter()
        .map(|function| hir_function_operation(context, function))
        .collect::<mlir::Result<Vec<_>>>()?;
    crate::irs::mlir::operation(
        context,
        "binlex.hir.module",
        vec![crate::irs::mlir::string_attr(context, "sym_name", &name)],
        vec![crate::irs::mlir::region_with_ops(ops)],
    )
}

fn format_parameter(parameter: &HirParameter) -> String {
    format!("%{}: {}", parameter.name, format_type(&parameter.ty))
}

fn format_local(local: &HirLocal) -> String {
    match &local.init {
        Some(init) => format!(
            "let %{}: {} = {};",
            local.name,
            format_type(&local.ty),
            format_expression(init)
        ),
        None => format!("let %{}: {};", local.name, format_type(&local.ty)),
    }
}

struct HirFormatter {
    local_types: BTreeMap<String, HirType>,
    declared: BTreeSet<String>,
    explicit_locals: Vec<HirLocal>,
    referenced_labels: BTreeSet<String>,
}

impl HirFormatter {
    fn new(hir: &HirFunction) -> Self {
        let local_types = hir
            .locals
            .iter()
            .map(|local| (local.name.clone(), local.ty.clone()))
            .collect::<BTreeMap<_, _>>();
        let explicit_locals = hir
            .locals
            .iter()
            .filter(|local| local.init.is_some() || !is_generated_temp_name(&local.name))
            .cloned()
            .collect::<Vec<_>>();
        let mut declared = hir
            .parameters
            .iter()
            .map(|parameter| parameter.name.clone())
            .collect::<BTreeSet<_>>();
        declared.extend(explicit_locals.iter().map(|local| local.name.clone()));
        let mut referenced_labels = BTreeSet::new();
        for block in &hir.blocks {
            collect_printed_label_references_in_block(block, &mut referenced_labels);
        }
        Self {
            local_types,
            declared,
            explicit_locals,
            referenced_labels,
        }
    }

    fn format_block(&mut self, block: &HirBlock, indent: usize, lines: &mut Vec<String>) {
        let inherited_cloneable_regions = BTreeMap::new();
        self.format_block_with_regions(block, indent, lines, &inherited_cloneable_regions);
    }

    fn format_block_with_regions(
        &mut self,
        block: &HirBlock,
        indent: usize,
        lines: &mut Vec<String>,
        inherited_cloneable_regions: &BTreeMap<String, HirBlock>,
    ) {
        let inlineable_regions = find_inlineable_label_regions(&block.statements);
        let cloneable_regions = find_cloneable_label_regions(&block.statements);
        let cloneable_fallthrough_regions =
            find_cloneable_fallthrough_label_regions(&block.statements);
        let mut nested_cloneable_regions = inherited_cloneable_regions.clone();
        nested_cloneable_regions.extend(collect_cloneable_region_bodies(
            &block.statements,
            &cloneable_regions,
        ));
        nested_cloneable_regions.extend(collect_cloneable_region_bodies(
            &block.statements,
            &cloneable_fallthrough_regions,
        ));
        let mut skipped_region_starts = BTreeMap::new();
        let mut index = 0;
        while index < block.statements.len() {
            if let Some(end) = skipped_region_starts.remove(&index) {
                index = end;
                continue;
            }

            if vacuous_guard_to_next_label(&block.statements, index) {
                index += 1;
                continue;
            }

            if let Some((body, label_index, end_index)) =
                inlineable_region_for_goto(&block.statements, index, &inlineable_regions)
            {
                self.format_block_with_regions(&body, indent, lines, inherited_cloneable_regions);
                skipped_region_starts.insert(label_index, end_index);
                index += 1;
                continue;
            }

            if let Some((condition, body, label_index, end_index)) =
                inlineable_region_for_if_goto(&block.statements, index, &inlineable_regions)
            {
                let prefix = "  ".repeat(indent);
                lines.push(format!("{prefix}if ({}) {{", format_expression(&condition)));
                self.format_block_with_regions(
                    &body,
                    indent + 1,
                    lines,
                    inherited_cloneable_regions,
                );
                lines.push(format!("{prefix}}}"));
                skipped_region_starts.insert(label_index, end_index);
                index += 1;
                continue;
            }

            if let Some(body) =
                cloneable_region_for_goto(&block.statements, index, &cloneable_regions)
            {
                self.format_block_with_regions(&body, indent, lines, inherited_cloneable_regions);
                index += 1;
                continue;
            }

            if let Some((condition, body)) =
                cloneable_region_for_if_goto(&block.statements, index, &cloneable_regions)
            {
                let prefix = "  ".repeat(indent);
                lines.push(format!("{prefix}if ({}) {{", format_expression(&condition)));
                self.format_block_with_regions(
                    &body,
                    indent + 1,
                    lines,
                    inherited_cloneable_regions,
                );
                lines.push(format!("{prefix}}}"));
                index += 1;
                continue;
            }

            if let Some(body) = cloneable_fallthrough_region_for_goto(
                &block.statements,
                index,
                &cloneable_fallthrough_regions,
            ) {
                self.format_block_with_regions(&body, indent, lines, inherited_cloneable_regions);
                index += 1;
                continue;
            }

            if let Some((condition, body)) = cloneable_fallthrough_region_for_if_goto(
                &block.statements,
                index,
                &cloneable_fallthrough_regions,
            ) {
                let prefix = "  ".repeat(indent);
                lines.push(format!("{prefix}if ({}) {{", format_expression(&condition)));
                self.format_block_with_regions(
                    &body,
                    indent + 1,
                    lines,
                    inherited_cloneable_regions,
                );
                lines.push(format!("{prefix}}}"));
                index += 1;
                continue;
            }

            if let Some(body) = external_cloneable_region_for_goto(
                &block.statements[index],
                inherited_cloneable_regions,
            ) {
                let empty_regions = BTreeMap::new();
                self.format_block_with_regions(&body, indent, lines, &empty_regions);
                index += 1;
                continue;
            }

            if let Some((condition, body)) = external_cloneable_region_for_if_goto(
                &block.statements[index],
                inherited_cloneable_regions,
            ) {
                let prefix = "  ".repeat(indent);
                lines.push(format!("{prefix}if ({}) {{", format_expression(&condition)));
                let empty_regions = BTreeMap::new();
                self.format_block_with_regions(&body, indent + 1, lines, &empty_regions);
                lines.push(format!("{prefix}}}"));
                index += 1;
                continue;
            }

            if let Some((target, consumed)) = find_redundant_goto_branch(&block.statements, index) {
                lines.push(format!(
                    "{}goto {};",
                    "  ".repeat(indent),
                    format_code_location(&target)
                ));
                index += consumed;
                continue;
            }

            if let Some((loop_body, consumed)) =
                find_printable_loop_region(&block.statements, index)
            {
                let prefix = "  ".repeat(indent);
                lines.push(format!("{prefix}loop {{"));
                self.format_block_with_regions(
                    &loop_body,
                    indent + 1,
                    lines,
                    inherited_cloneable_regions,
                );
                lines.push(format!("{prefix}}}"));
                index += consumed;
                continue;
            }

            if let Some((guard_condition, consumed, label_index)) =
                find_printable_guard_region(&block.statements, index)
            {
                let prefix = "  ".repeat(indent);
                lines.push(format!(
                    "{prefix}if ({}) {{",
                    format_expression(&negate_printable_condition(guard_condition))
                ));
                let guarded = HirBlock {
                    statements: block.statements[(index + consumed)..label_index].to_vec(),
                };
                self.format_block_with_regions(
                    &guarded,
                    indent + 1,
                    lines,
                    inherited_cloneable_regions,
                );
                lines.push(format!("{prefix}}}"));
                index = label_index;
                continue;
            }

            if let Some((guard_statement, consumed)) =
                merge_printable_guard_jump_run(&block.statements, index)
            {
                self.format_statement(&guard_statement, indent, lines);
                index += consumed;
                continue;
            }

            if let Some(rewritten) = rewrite_if_tail_guard_to_next_label(&block.statements, index) {
                self.format_statement_with_regions(
                    &rewritten,
                    indent,
                    lines,
                    &nested_cloneable_regions,
                );
                index += 1;
                continue;
            }

            self.format_statement_with_regions(
                &block.statements[index],
                indent,
                lines,
                &nested_cloneable_regions,
            );
            index += 1;
        }
    }

    fn format_statement(
        &mut self,
        statement: &HirStatement,
        indent: usize,
        lines: &mut Vec<String>,
    ) {
        let inherited_cloneable_regions = BTreeMap::new();
        self.format_statement_with_regions(statement, indent, lines, &inherited_cloneable_regions);
    }

    fn format_statement_with_regions(
        &mut self,
        statement: &HirStatement,
        indent: usize,
        lines: &mut Vec<String>,
        inherited_cloneable_regions: &BTreeMap<String, HirBlock>,
    ) {
        let prefix = "  ".repeat(indent);
        match statement {
            HirStatement::Assign { target, value } => {
                if let HirPlace::Named { name, .. } = target {
                    if !self.declared.contains(name) {
                        if let Some(ty) = self.local_types.get(name) {
                            lines.push(format!(
                                "{prefix}let %{}: {} = {};",
                                name,
                                format_type(ty),
                                format_expression(value)
                            ));
                            self.declared.insert(name.clone());
                            return;
                        }
                    }
                }
                lines.push(format!(
                    "{prefix}{} = {};",
                    format_place(target),
                    format_expression(value)
                ));
            }
            HirStatement::Expr(value) => {
                lines.push(format!("{prefix}{};", format_expression(value)))
            }
            HirStatement::If { .. } => {
                if let Some((condition, target)) = extract_printable_guard_jump(statement) {
                    lines.push(format!("{prefix}if ({}) {{", format_expression(&condition)));
                    lines.push(format!(
                        "{}goto {};",
                        "  ".repeat(indent + 1),
                        format_code_location(&target)
                    ));
                    lines.push(format!("{prefix}}}"));
                    return;
                }

                let HirStatement::If {
                    condition,
                    then_body,
                    else_body,
                } = statement
                else {
                    unreachable!();
                };
                lines.push(format!("{prefix}if ({}) {{", format_expression(condition)));
                self.format_block_with_regions(
                    then_body,
                    indent + 1,
                    lines,
                    inherited_cloneable_regions,
                );
                if let Some(else_body) = else_body {
                    lines.push(format!("{prefix}}} else {{"));
                    self.format_block_with_regions(
                        else_body,
                        indent + 1,
                        lines,
                        inherited_cloneable_regions,
                    );
                }
                lines.push(format!("{prefix}}}"));
            }
            HirStatement::While { condition, body } => {
                lines.push(format!(
                    "{prefix}while ({}) {{",
                    format_expression(condition)
                ));
                self.format_block_with_regions(
                    body,
                    indent + 1,
                    lines,
                    inherited_cloneable_regions,
                );
                lines.push(format!("{prefix}}}"));
            }
            HirStatement::Loop { body } => {
                lines.push(format!("{prefix}loop {{"));
                self.format_block_with_regions(
                    body,
                    indent + 1,
                    lines,
                    inherited_cloneable_regions,
                );
                lines.push(format!("{prefix}}}"));
            }
            HirStatement::Switch {
                value,
                cases,
                default,
            } => {
                lines.push(format!("{prefix}switch ({}) {{", format_expression(value)));
                for case in cases {
                    self.format_switch_case(case, indent + 1, lines);
                }
                if let Some(default) = default {
                    lines.push(format!("{}default {{", "  ".repeat(indent + 1)));
                    self.format_block_with_regions(
                        default,
                        indent + 2,
                        lines,
                        inherited_cloneable_regions,
                    );
                    lines.push(format!("{}}}", "  ".repeat(indent + 1)));
                }
                lines.push(format!("{prefix}}}"));
            }
            HirStatement::Break => lines.push(format!("{prefix}break;")),
            HirStatement::Continue => lines.push(format!("{prefix}continue;")),
            HirStatement::Return { values } => {
                if values.is_empty() {
                    lines.push(format!("{prefix}return;"));
                } else {
                    lines.push(format!(
                        "{prefix}return {};",
                        values
                            .iter()
                            .map(format_expression)
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
            }
            HirStatement::Label(name) => {
                if self.referenced_labels.contains(name) {
                    lines.push(format!("{prefix}label {}:", format_code_location(name)));
                }
            }
            HirStatement::Goto(target) => {
                lines.push(format!("{prefix}goto {};", format_target(target)))
            }
            HirStatement::Trap => lines.push(format!("{prefix}trap;")),
            HirStatement::Unreachable => lines.push(format!("{prefix}unreachable;")),
        }
    }

    fn format_switch_case(&mut self, case: &HirSwitchCase, indent: usize, lines: &mut Vec<String>) {
        let prefix = "  ".repeat(indent);
        lines.push(format!("{prefix}case {} {{", format_value(&case.value)));
        self.format_block(&case.body, indent + 1, lines);
        lines.push(format!("{prefix}}}"));
    }
}

fn merge_printable_guard_jump_run(
    statements: &[HirStatement],
    start: usize,
) -> Option<(HirStatement, usize)> {
    let (condition, target) = extract_printable_guard_jump(statements.get(start)?)?;
    let mut merged = condition;
    let mut consumed = 1;

    for statement in &statements[(start + 1)..] {
        let Some((next_condition, next_target)) = extract_printable_guard_jump(statement) else {
            break;
        };
        if next_target != target {
            break;
        }
        merged = HirExpression::Binary {
            op: HirBinaryOperation::Or,
            lhs: Box::new(merged),
            rhs: Box::new(next_condition),
            ty: HirType::integer(1),
        };
        consumed += 1;
    }

    if consumed < 2 {
        return None;
    }

    Some((
        HirStatement::If {
            condition: merged,
            then_body: HirBlock {
                statements: vec![HirStatement::Goto(HirTarget::Direct(target))],
            },
            else_body: None,
        },
        consumed,
    ))
}

fn find_printable_guard_region(
    statements: &[HirStatement],
    start: usize,
) -> Option<(HirExpression, usize, usize)> {
    let (guard_condition, target, consumed) =
        if let Some((statement, consumed)) = merge_printable_guard_jump_run(statements, start) {
            let (condition, target) = extract_printable_guard_jump(&statement)?;
            (condition, target, consumed)
        } else {
            let (condition, target) = extract_printable_guard_jump(statements.get(start)?)?;
            (condition, target, 1)
        };

    let label_index = ((start + consumed)..statements.len())
        .find(|index| label_name(&statements[*index]) == Some(target.as_str()))?;
    if label_index <= start + consumed {
        return None;
    }
    if !printable_region_internal_labels_are_self_contained(
        statements,
        start + consumed,
        label_index,
    ) {
        return None;
    }
    Some((guard_condition, consumed, label_index))
}

fn rewrite_if_tail_guard_to_next_label(
    statements: &[HirStatement],
    index: usize,
) -> Option<HirStatement> {
    let HirStatement::If {
        condition,
        then_body,
        else_body,
    } = statements.get(index)?
    else {
        return None;
    };
    if else_body.is_some() {
        return None;
    }
    let next_label = label_name(statements.get(index + 1)?)?;
    let rewritten_then = rewrite_guard_to_external_label(then_body, next_label)?;
    Some(HirStatement::If {
        condition: condition.clone(),
        then_body: rewritten_then,
        else_body: None,
    })
}

fn rewrite_guard_to_external_label(block: &HirBlock, target_label: &str) -> Option<HirBlock> {
    for start in 0..block.statements.len() {
        let (condition, consumed) = if let Some((statement, consumed)) =
            merge_printable_guard_jump_run(&block.statements, start)
        {
            let (condition, target) = extract_printable_guard_jump(&statement)?;
            if target != target_label {
                continue;
            }
            (condition, consumed)
        } else {
            let (condition, target) = extract_printable_guard_jump(block.statements.get(start)?)?;
            if target != target_label {
                continue;
            }
            (condition, 1)
        };

        let guarded_start = start + consumed;
        if guarded_start >= block.statements.len() {
            continue;
        }
        if !printable_region_internal_labels_are_self_contained(
            &block.statements,
            guarded_start,
            block.statements.len(),
        ) {
            continue;
        }

        let mut rewritten = block.statements[..start].to_vec();
        rewritten.push(HirStatement::If {
            condition: negate_printable_condition(condition),
            then_body: HirBlock {
                statements: block.statements[guarded_start..].to_vec(),
            },
            else_body: None,
        });
        return Some(HirBlock {
            statements: rewritten,
        });
    }

    None
}

fn find_inlineable_label_regions(statements: &[HirStatement]) -> BTreeMap<String, (usize, usize)> {
    let label_counts = count_label_references_in_statements(statements);
    let mut regions = BTreeMap::new();
    let label_positions = statements
        .iter()
        .enumerate()
        .filter_map(|(index, statement)| {
            label_name(statement).map(|name| (index, name.to_string()))
        })
        .collect::<Vec<_>>();

    for (position, (index, label)) in label_positions.iter().enumerate() {
        if label_counts.get(label).copied().unwrap_or(0) != 1 || *index == 0 {
            continue;
        }
        if !statement_blocks_fallthrough(&statements[index - 1]) {
            continue;
        }
        let end = label_positions
            .get(position + 1)
            .map(|(next_index, _)| *next_index)
            .unwrap_or(statements.len());
        if statements[(*index + 1)..end]
            .iter()
            .any(|statement| matches!(statement, HirStatement::Label(_)))
        {
            continue;
        }
        regions.insert(label.clone(), (*index, end));
    }

    regions
}

fn find_cloneable_label_regions(statements: &[HirStatement]) -> BTreeMap<String, (usize, usize)> {
    const MAX_CLONEABLE_REGION_STATEMENTS: usize = 8;

    let label_counts = count_label_references_in_statements(statements);
    let mut regions = BTreeMap::new();
    let label_positions = statements
        .iter()
        .enumerate()
        .filter_map(|(index, statement)| {
            label_name(statement).map(|name| (index, name.to_string()))
        })
        .collect::<Vec<_>>();

    for (position, (index, label)) in label_positions.iter().enumerate() {
        let ref_count = label_counts.get(label).copied().unwrap_or(0);
        if ref_count == 0 || ref_count > 2 {
            continue;
        }
        let end = label_positions
            .get(position + 1)
            .map(|(next_index, _)| *next_index)
            .unwrap_or(statements.len());
        let body = &statements[(*index + 1)..end];
        if body.is_empty() || body.len() > MAX_CLONEABLE_REGION_STATEMENTS {
            continue;
        }
        if printable_clone_cost(body) > 14 {
            continue;
        }
        if !cloneable_terminal_region(body) {
            continue;
        }
        regions.insert(label.clone(), (*index, end));
    }

    regions
}

fn find_cloneable_fallthrough_label_regions(
    statements: &[HirStatement],
) -> BTreeMap<String, (usize, usize)> {
    const MAX_CLONEABLE_FALLTHROUGH_STATEMENTS: usize = 16;

    let label_counts = count_label_references_in_statements(statements);
    let mut regions = BTreeMap::new();
    let label_positions = statements
        .iter()
        .enumerate()
        .filter_map(|(index, statement)| {
            label_name(statement).map(|name| (index, name.to_string()))
        })
        .collect::<Vec<_>>();

    for (position, (index, label)) in label_positions.iter().enumerate() {
        if *index == 0 {
            continue;
        }
        let ref_count = label_counts.get(label).copied().unwrap_or(0);
        if ref_count == 0 || ref_count > 2 {
            continue;
        }
        if statement_blocks_fallthrough(&statements[index - 1]) {
            continue;
        }
        let end = label_positions
            .get(position + 1)
            .map(|(next_index, _)| *next_index)
            .unwrap_or(statements.len());
        let body = &statements[(*index + 1)..end];
        if body.is_empty() || body.len() > MAX_CLONEABLE_FALLTHROUGH_STATEMENTS {
            continue;
        }
        if printable_clone_cost(body) > 14 {
            continue;
        }
        if !cloneable_fallthrough_region(body) {
            continue;
        }
        regions.insert(label.clone(), (*index, end));
    }

    regions
}

fn inlineable_region_for_goto(
    statements: &[HirStatement],
    index: usize,
    regions: &BTreeMap<String, (usize, usize)>,
) -> Option<(HirBlock, usize, usize)> {
    let HirStatement::Goto(HirTarget::Direct(target)) = statements.get(index)? else {
        return None;
    };
    let (label_index, end_index) = *regions.get(target)?;
    if label_index <= index {
        return None;
    }
    Some((
        HirBlock {
            statements: statements[(label_index + 1)..end_index].to_vec(),
        },
        label_index,
        end_index,
    ))
}

fn inlineable_region_for_if_goto(
    statements: &[HirStatement],
    index: usize,
    regions: &BTreeMap<String, (usize, usize)>,
) -> Option<(HirExpression, HirBlock, usize, usize)> {
    let HirStatement::If {
        condition,
        then_body,
        else_body,
    } = statements.get(index)?
    else {
        return None;
    };
    if else_body.is_some() {
        return None;
    }
    let target = single_direct_goto_target(then_body)?;
    let (label_index, end_index) = *regions.get(target)?;
    if label_index <= index {
        return None;
    }
    Some((
        condition.clone(),
        HirBlock {
            statements: statements[(label_index + 1)..end_index].to_vec(),
        },
        label_index,
        end_index,
    ))
}

fn cloneable_region_for_goto(
    statements: &[HirStatement],
    index: usize,
    regions: &BTreeMap<String, (usize, usize)>,
) -> Option<HirBlock> {
    let HirStatement::Goto(HirTarget::Direct(target)) = statements.get(index)? else {
        return None;
    };
    let (label_index, end_index) = *regions.get(target)?;
    if label_index <= index {
        return None;
    }
    Some(HirBlock {
        statements: statements[(label_index + 1)..end_index].to_vec(),
    })
}

fn cloneable_region_for_if_goto(
    statements: &[HirStatement],
    index: usize,
    regions: &BTreeMap<String, (usize, usize)>,
) -> Option<(HirExpression, HirBlock)> {
    let HirStatement::If {
        condition,
        then_body,
        else_body,
    } = statements.get(index)?
    else {
        return None;
    };
    if else_body.is_some() {
        return None;
    }
    let target = single_direct_goto_target(then_body)?;
    let (label_index, end_index) = *regions.get(target)?;
    if label_index <= index {
        return None;
    }
    Some((
        condition.clone(),
        HirBlock {
            statements: statements[(label_index + 1)..end_index].to_vec(),
        },
    ))
}

fn cloneable_fallthrough_region_for_goto(
    statements: &[HirStatement],
    index: usize,
    regions: &BTreeMap<String, (usize, usize)>,
) -> Option<HirBlock> {
    let HirStatement::Goto(HirTarget::Direct(target)) = statements.get(index)? else {
        return None;
    };
    let (label_index, end_index) = *regions.get(target)?;
    if label_index <= index {
        return None;
    }
    Some(HirBlock {
        statements: statements[(label_index + 1)..end_index].to_vec(),
    })
}

fn cloneable_fallthrough_region_for_if_goto(
    statements: &[HirStatement],
    index: usize,
    regions: &BTreeMap<String, (usize, usize)>,
) -> Option<(HirExpression, HirBlock)> {
    let HirStatement::If {
        condition,
        then_body,
        else_body,
    } = statements.get(index)?
    else {
        return None;
    };
    if else_body.is_some() {
        return None;
    }
    let target = single_direct_goto_target(then_body)?;
    let (label_index, end_index) = *regions.get(target)?;
    if label_index <= index {
        return None;
    }
    Some((
        condition.clone(),
        HirBlock {
            statements: statements[(label_index + 1)..end_index].to_vec(),
        },
    ))
}

fn collect_cloneable_region_bodies(
    statements: &[HirStatement],
    regions: &BTreeMap<String, (usize, usize)>,
) -> BTreeMap<String, HirBlock> {
    let mut bodies = BTreeMap::new();
    for (label, (label_index, end_index)) in regions {
        bodies.insert(
            label.clone(),
            HirBlock {
                statements: statements[(label_index + 1)..*end_index].to_vec(),
            },
        );
    }
    bodies
}

fn external_cloneable_region_for_goto(
    statement: &HirStatement,
    regions: &BTreeMap<String, HirBlock>,
) -> Option<HirBlock> {
    let HirStatement::Goto(HirTarget::Direct(target)) = statement else {
        return None;
    };
    let body = regions.get(target)?;
    if !externally_cloneable_terminal_region(body) {
        return None;
    }
    Some(body.clone())
}

fn external_cloneable_region_for_if_goto(
    statement: &HirStatement,
    regions: &BTreeMap<String, HirBlock>,
) -> Option<(HirExpression, HirBlock)> {
    let HirStatement::If {
        condition,
        then_body,
        else_body,
    } = statement
    else {
        return None;
    };
    if else_body.is_some() {
        return None;
    }
    let target = single_direct_goto_target(then_body)?;
    let body = regions.get(target)?;
    if !externally_cloneable_terminal_region(body) {
        return None;
    }
    Some((condition.clone(), body.clone()))
}

fn externally_cloneable_terminal_region(block: &HirBlock) -> bool {
    let statements = &block.statements;
    if statements.is_empty() || statements.len() > 4 {
        return false;
    }
    cloneable_terminal_region(statements)
}

fn cloneable_terminal_region(statements: &[HirStatement]) -> bool {
    match statements.last() {
        Some(HirStatement::Return { .. } | HirStatement::Trap | HirStatement::Unreachable) => {}
        _ => return false,
    }

    statements.iter().all(|statement| {
        matches!(
            statement,
            HirStatement::Assign { .. }
                | HirStatement::Expr(_)
                | HirStatement::Return { .. }
                | HirStatement::Trap
                | HirStatement::Unreachable
        )
    })
}

fn cloneable_fallthrough_region(statements: &[HirStatement]) -> bool {
    match statements.last() {
        Some(
            HirStatement::Goto(_)
            | HirStatement::Return { .. }
            | HirStatement::Trap
            | HirStatement::Unreachable,
        ) => {}
        _ => return false,
    }

    statements.iter().all(|statement| {
        matches!(
            statement,
            HirStatement::Assign { .. }
                | HirStatement::Expr(_)
                | HirStatement::If { .. }
                | HirStatement::Goto(_)
                | HirStatement::Return { .. }
                | HirStatement::Trap
                | HirStatement::Unreachable
        )
    })
}

fn printable_clone_cost(statements: &[HirStatement]) -> usize {
    statements.iter().map(printable_statement_clone_cost).sum()
}

fn printable_statement_clone_cost(statement: &HirStatement) -> usize {
    match statement {
        HirStatement::If {
            then_body,
            else_body,
            ..
        } => {
            2 + printable_clone_cost(&then_body.statements)
                + else_body
                    .as_ref()
                    .map(|else_body| printable_clone_cost(&else_body.statements))
                    .unwrap_or(0)
        }
        HirStatement::While { .. } | HirStatement::Loop { .. } | HirStatement::Switch { .. } => 100,
        HirStatement::Label(_) => 100,
        _ => 1,
    }
}

fn statement_blocks_fallthrough(statement: &HirStatement) -> bool {
    matches!(
        statement,
        HirStatement::Goto(_)
            | HirStatement::Return { .. }
            | HirStatement::Break
            | HirStatement::Continue
            | HirStatement::Trap
            | HirStatement::Unreachable
    )
}

fn collect_printed_label_references_in_block(block: &HirBlock, labels: &mut BTreeSet<String>) {
    let inherited_cloneable_regions = BTreeMap::new();
    collect_printed_label_references_in_block_with_regions(
        block,
        labels,
        &inherited_cloneable_regions,
    );
}

fn collect_printed_label_references_in_block_with_regions(
    block: &HirBlock,
    labels: &mut BTreeSet<String>,
    inherited_cloneable_regions: &BTreeMap<String, HirBlock>,
) {
    let inlineable_regions = find_inlineable_label_regions(&block.statements);
    let cloneable_regions = find_cloneable_label_regions(&block.statements);
    let cloneable_fallthrough_regions = find_cloneable_fallthrough_label_regions(&block.statements);
    let mut nested_cloneable_regions = inherited_cloneable_regions.clone();
    nested_cloneable_regions.extend(collect_cloneable_region_bodies(
        &block.statements,
        &cloneable_regions,
    ));
    nested_cloneable_regions.extend(collect_cloneable_region_bodies(
        &block.statements,
        &cloneable_fallthrough_regions,
    ));
    let mut skipped_region_starts = BTreeMap::new();
    let mut index = 0;

    while index < block.statements.len() {
        if let Some(end) = skipped_region_starts.remove(&index) {
            index = end;
            continue;
        }

        if let Some((body, label_index, end_index)) =
            inlineable_region_for_goto(&block.statements, index, &inlineable_regions)
        {
            collect_printed_label_references_in_block_with_regions(
                &body,
                labels,
                inherited_cloneable_regions,
            );
            skipped_region_starts.insert(label_index, end_index);
            index += 1;
            continue;
        }

        if let Some((_condition, body, label_index, end_index)) =
            inlineable_region_for_if_goto(&block.statements, index, &inlineable_regions)
        {
            collect_printed_label_references_in_block_with_regions(
                &body,
                labels,
                inherited_cloneable_regions,
            );
            skipped_region_starts.insert(label_index, end_index);
            index += 1;
            continue;
        }

        if let Some(body) = cloneable_region_for_goto(&block.statements, index, &cloneable_regions)
        {
            collect_printed_label_references_in_block_with_regions(
                &body,
                labels,
                inherited_cloneable_regions,
            );
            index += 1;
            continue;
        }

        if let Some((_condition, body)) =
            cloneable_region_for_if_goto(&block.statements, index, &cloneable_regions)
        {
            collect_printed_label_references_in_block_with_regions(
                &body,
                labels,
                inherited_cloneable_regions,
            );
            index += 1;
            continue;
        }

        if let Some(body) = cloneable_fallthrough_region_for_goto(
            &block.statements,
            index,
            &cloneable_fallthrough_regions,
        ) {
            collect_printed_label_references_in_block_with_regions(
                &body,
                labels,
                inherited_cloneable_regions,
            );
            index += 1;
            continue;
        }

        if let Some((_condition, body)) = cloneable_fallthrough_region_for_if_goto(
            &block.statements,
            index,
            &cloneable_fallthrough_regions,
        ) {
            collect_printed_label_references_in_block_with_regions(
                &body,
                labels,
                inherited_cloneable_regions,
            );
            index += 1;
            continue;
        }

        if let Some(body) = external_cloneable_region_for_goto(
            &block.statements[index],
            inherited_cloneable_regions,
        ) {
            let empty_regions = BTreeMap::new();
            collect_printed_label_references_in_block_with_regions(&body, labels, &empty_regions);
            index += 1;
            continue;
        }

        if let Some((_condition, body)) = external_cloneable_region_for_if_goto(
            &block.statements[index],
            inherited_cloneable_regions,
        ) {
            let empty_regions = BTreeMap::new();
            collect_printed_label_references_in_block_with_regions(&body, labels, &empty_regions);
            index += 1;
            continue;
        }

        if let Some((target, consumed)) = find_redundant_goto_branch(&block.statements, index) {
            labels.insert(target);
            index += consumed;
            continue;
        }

        if let Some((loop_body, consumed)) = find_printable_loop_region(&block.statements, index) {
            collect_printed_label_references_in_block_with_regions(
                &loop_body,
                labels,
                inherited_cloneable_regions,
            );
            index += consumed;
            continue;
        }

        if let Some((_guard_condition, consumed, label_index)) =
            find_printable_guard_region(&block.statements, index)
        {
            let guarded = HirBlock {
                statements: block.statements[(index + consumed)..label_index].to_vec(),
            };
            collect_printed_label_references_in_block_with_regions(
                &guarded,
                labels,
                inherited_cloneable_regions,
            );
            index = label_index;
            continue;
        }

        if let Some((guard_statement, consumed)) =
            merge_printable_guard_jump_run(&block.statements, index)
        {
            collect_printed_label_references_in_statement_with_regions(
                &guard_statement,
                labels,
                &nested_cloneable_regions,
            );
            index += consumed;
            continue;
        }

        if let Some(rewritten) = rewrite_if_tail_guard_to_next_label(&block.statements, index) {
            collect_printed_label_references_in_statement_with_regions(
                &rewritten,
                labels,
                &nested_cloneable_regions,
            );
            index += 1;
            continue;
        }

        collect_printed_label_references_in_statement_with_regions(
            &block.statements[index],
            labels,
            &nested_cloneable_regions,
        );
        index += 1;
    }
}

fn collect_printed_label_references_in_statement_with_regions(
    statement: &HirStatement,
    labels: &mut BTreeSet<String>,
    inherited_cloneable_regions: &BTreeMap<String, HirBlock>,
) {
    match statement {
        HirStatement::If {
            then_body,
            else_body,
            ..
        } => {
            collect_printed_label_references_in_block_with_regions(
                then_body,
                labels,
                inherited_cloneable_regions,
            );
            if let Some(else_body) = else_body {
                collect_printed_label_references_in_block_with_regions(
                    else_body,
                    labels,
                    inherited_cloneable_regions,
                );
            }
        }
        HirStatement::While { body, .. } | HirStatement::Loop { body } => {
            collect_printed_label_references_in_block_with_regions(
                body,
                labels,
                inherited_cloneable_regions,
            );
        }
        HirStatement::Switch { cases, default, .. } => {
            for case in cases {
                collect_printed_label_references_in_block_with_regions(
                    &case.body,
                    labels,
                    inherited_cloneable_regions,
                );
            }
            if let Some(default) = default {
                collect_printed_label_references_in_block_with_regions(
                    default,
                    labels,
                    inherited_cloneable_regions,
                );
            }
        }
        HirStatement::Goto(HirTarget::Direct(target)) => {
            labels.insert(target.clone());
        }
        HirStatement::Assign { .. }
        | HirStatement::Expr(_)
        | HirStatement::Break
        | HirStatement::Continue
        | HirStatement::Return { .. }
        | HirStatement::Label(_)
        | HirStatement::Goto(HirTarget::Indirect(_))
        | HirStatement::Trap
        | HirStatement::Unreachable => {}
    }
}

fn vacuous_guard_to_next_label(statements: &[HirStatement], index: usize) -> bool {
    let Some((_, target)) =
        extract_printable_guard_jump(statements.get(index).unwrap_or(&HirStatement::Trap))
    else {
        return false;
    };
    matches!(
        statements.get(index + 1),
        Some(HirStatement::Label(label)) if label == &target
    )
}

fn find_redundant_goto_branch(
    statements: &[HirStatement],
    start: usize,
) -> Option<(String, usize)> {
    let HirStatement::If {
        then_body,
        else_body,
        ..
    } = statements.get(start)?
    else {
        return None;
    };

    let target = single_direct_goto_target(then_body)?.to_string();

    if else_body.is_none()
        && matches!(
            statements.get(start + 1),
            Some(HirStatement::Goto(HirTarget::Direct(next))) if next == &target
        )
    {
        return Some((target, 2));
    }

    let else_body = else_body.as_ref()?;
    let else_target = single_direct_goto_target(else_body)?;
    if else_target == target {
        return Some((target, 1));
    }

    None
}

fn find_printable_loop_region(
    statements: &[HirStatement],
    start: usize,
) -> Option<(HirBlock, usize)> {
    let loop_label = label_name(statements.get(start)?)?.to_string();
    let mut backedge_index = None;
    let mut backedge_condition = None;

    for index in (start + 1)..statements.len() {
        if index > start + 1 && label_name(&statements[index]).is_some() {
            break;
        }

        if let HirStatement::Goto(HirTarget::Direct(target)) = &statements[index] {
            if target == &loop_label {
                backedge_index = Some(index);
                break;
            }
        }

        if let Some((condition, target)) = extract_printable_guard_jump(&statements[index]) {
            if target == loop_label {
                backedge_index = Some(index);
                backedge_condition = Some(condition);
                break;
            }
        }
    }

    let backedge_index = backedge_index?;
    if backedge_index <= start + 1 {
        return None;
    }

    let mut loop_body = HirBlock {
        statements: statements[(start + 1)..backedge_index].to_vec(),
    };
    if let Some(condition) = backedge_condition {
        loop_body.statements.push(HirStatement::If {
            condition: negate_printable_condition(condition),
            then_body: HirBlock {
                statements: vec![HirStatement::Break],
            },
            else_body: None,
        });
    }

    Some((loop_body, backedge_index + 1 - start))
}

fn extract_printable_guard_jump(statement: &HirStatement) -> Option<(HirExpression, String)> {
    let HirStatement::If {
        condition,
        then_body,
        else_body,
    } = statement
    else {
        return None;
    };

    if else_body.is_some() {
        return None;
    }

    if let Some(target) = single_direct_goto_target(then_body) {
        return Some((condition.clone(), target.to_string()));
    }

    let nested = match then_body.statements.as_slice() {
        [nested] => nested,
        _ => return None,
    };
    let (nested_condition, target) = extract_printable_guard_jump(nested)?;
    Some((
        HirExpression::Binary {
            op: HirBinaryOperation::And,
            lhs: Box::new(condition.clone()),
            rhs: Box::new(nested_condition),
            ty: HirType::integer(1),
        },
        target,
    ))
}

fn single_direct_goto_target(block: &HirBlock) -> Option<&str> {
    match block.statements.as_slice() {
        [HirStatement::Goto(HirTarget::Direct(target))] => Some(target.as_str()),
        _ => None,
    }
}

fn label_name(statement: &HirStatement) -> Option<&str> {
    match statement {
        HirStatement::Label(name) => Some(name.as_str()),
        _ => None,
    }
}

fn negate_printable_condition(condition: HirExpression) -> HirExpression {
    match condition {
        HirExpression::Unary {
            op: HirUnaryOperation::LogicalNot,
            value,
            ..
        } => *value,
        other => HirExpression::Unary {
            op: HirUnaryOperation::LogicalNot,
            ty: HirType::integer(1),
            value: Box::new(other),
        },
    }
}

fn printable_region_internal_labels_are_self_contained(
    statements: &[HirStatement],
    start: usize,
    end: usize,
) -> bool {
    let internal_labels: BTreeSet<String> = statements[start..end]
        .iter()
        .filter_map(|statement| match statement {
            HirStatement::Label(name) => Some(name.clone()),
            _ => None,
        })
        .collect();

    if internal_labels.is_empty() {
        return true;
    }

    let whole_counts = count_label_references_in_statements(statements);
    let region_counts = count_label_references_in_statements(&statements[start..end]);

    internal_labels.into_iter().all(|label| {
        whole_counts.get(&label).copied().unwrap_or(0)
            == region_counts.get(&label).copied().unwrap_or(0)
    })
}

fn count_label_references_in_statements(statements: &[HirStatement]) -> BTreeMap<String, usize> {
    let mut labels = BTreeMap::new();
    for statement in statements {
        count_label_references_in_statement(statement, &mut labels);
    }
    labels
}

fn count_label_references_in_statement(
    statement: &HirStatement,
    labels: &mut BTreeMap<String, usize>,
) {
    match statement {
        HirStatement::If {
            then_body,
            else_body,
            ..
        } => {
            count_label_references_in_block(then_body, labels);
            if let Some(else_body) = else_body {
                count_label_references_in_block(else_body, labels);
            }
        }
        HirStatement::While { body, .. } | HirStatement::Loop { body } => {
            count_label_references_in_block(body, labels);
        }
        HirStatement::Switch { cases, default, .. } => {
            for case in cases {
                count_label_references_in_block(&case.body, labels);
            }
            if let Some(default) = default {
                count_label_references_in_block(default, labels);
            }
        }
        HirStatement::Goto(HirTarget::Direct(target)) => {
            *labels.entry(target.clone()).or_insert(0) += 1;
        }
        HirStatement::Assign { .. }
        | HirStatement::Expr(_)
        | HirStatement::Break
        | HirStatement::Continue
        | HirStatement::Return { .. }
        | HirStatement::Label(_)
        | HirStatement::Goto(HirTarget::Indirect(_))
        | HirStatement::Trap
        | HirStatement::Unreachable => {}
    }
}

fn count_label_references_in_block(block: &HirBlock, labels: &mut BTreeMap<String, usize>) {
    for statement in &block.statements {
        count_label_references_in_statement(statement, labels);
    }
}

fn is_generated_temp_name(name: &str) -> bool {
    [
        "bin_", "cmp_", "cast_", "select_", "call_", "extract_", "load", "ptr",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
}

fn format_expression(expression: &HirExpression) -> String {
    match expression {
        HirExpression::Value(value) => format_value(value),
        HirExpression::Unary {
            op: HirUnaryOperation::LogicalNot,
            value,
            ..
        } => format_negated_expression(value),
        HirExpression::Unary { op, value, .. } => {
            format!("{}{}", format_unary_op(*op), format_subexpression(value))
        }
        HirExpression::Binary { op, lhs, rhs, .. } => format!(
            "{} {} {}",
            format_subexpression(lhs),
            format_binary_op_expression(*op, expression),
            format_subexpression(rhs)
        ),
        HirExpression::Select {
            condition,
            when_true,
            when_false,
            ..
        } => format!(
            "select({}, {}, {})",
            format_expression(condition),
            format_expression(when_true),
            format_expression(when_false)
        ),
        HirExpression::Concat { parts, .. } => format!(
            "concat({})",
            parts
                .iter()
                .map(format_expression)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        HirExpression::Extract { value, lsb, .. } => {
            format!("extract({}, {})", format_expression(value), lsb)
        }
        HirExpression::Load {
            address_space,
            address,
            ty,
        } => {
            if matches!(address_space, super::kind::HirAddressSpace::Default) {
                format!(
                    "load [{}] : {}",
                    format_expression(address),
                    format_type(ty)
                )
            } else {
                format!(
                    "load {}[{}] : {}",
                    format_address_space(address_space),
                    format_expression(address),
                    format_type(ty)
                )
            }
        }
        HirExpression::Compare { op, lhs, rhs, .. } => format!(
            "{} {} {}",
            format_subexpression(lhs),
            format_compare_op(*op),
            format_subexpression(rhs)
        ),
        HirExpression::FloatCompare { op, lhs, rhs, .. } => format!(
            "fcmp.{}({}, {})",
            format_float_compare_op(*op),
            format_expression(lhs),
            format_expression(rhs)
        ),
        HirExpression::Cast { op, value, ty } => format!(
            "{}<{}>({})",
            format_cast_op(*op),
            format_type(ty),
            format_expression(value)
        ),
        HirExpression::Call {
            target, arguments, ..
        } => format!(
            "call {}({})",
            format_target(target),
            arguments
                .iter()
                .map(format_expression)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        HirExpression::Intrinsic {
            name, arguments, ..
        } => format!(
            "intrinsic {}({})",
            format_code_location(name),
            arguments
                .iter()
                .map(format_expression)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        HirExpression::AddressOf { place, .. } => format!("&{}", format_place(place)),
        HirExpression::Dereference { pointer, .. } => format!("*{}", format_subexpression(pointer)),
        HirExpression::Index { base, index, .. } => {
            format!(
                "{}[{}]",
                format_subexpression(base),
                format_expression(index)
            )
        }
    }
}

fn format_value(value: &HirValue) -> String {
    match value {
        HirValue::Named { name, .. } => format!("%{}", name),
        HirValue::Integer { value, bits } => format!("{value}:i{bits}"),
        HirValue::Boolean(value) => value.to_string(),
        HirValue::Null { ty } => format!("null:{}", format_type(ty)),
        HirValue::Undef { ty } => format!("undef:{}", format_type(ty)),
    }
}

fn format_place(place: &HirPlace) -> String {
    match place {
        HirPlace::Named { name, .. } => format!("%{}", name),
        HirPlace::Dereference { pointer, .. } => format!("*{}", format_subexpression(pointer)),
        HirPlace::Memory {
            address_space,
            address,
            ..
        } => {
            if matches!(address_space, super::kind::HirAddressSpace::Default) {
                format!("[{}]", format_expression(address))
            } else {
                format!(
                    "{}[{}]",
                    format_address_space(address_space),
                    format_expression(address)
                )
            }
        }
        HirPlace::Index { base, index, .. } => {
            format!(
                "{}[{}]",
                format_subexpression(base),
                format_expression(index)
            )
        }
    }
}

fn format_target(target: &HirTarget) -> String {
    match target {
        HirTarget::Direct(name) => format_code_location(name),
        HirTarget::Indirect(value) => format!("({})", format_expression(value)),
    }
}

fn format_type(ty: &HirType) -> String {
    match ty {
        HirType::Void => "void".to_string(),
        HirType::Integer(bits) => format!("i{bits}"),
        HirType::Float(bits) => format!("f{bits}"),
        HirType::Pointer { pointee } => format!("ptr<{}>", format_type(pointee)),
        HirType::Function {
            parameters,
            returns,
        } => format!(
            "fn({}) -> {}",
            parameters
                .iter()
                .map(format_type)
                .collect::<Vec<_>>()
                .join(", "),
            format_return_types(returns)
        ),
        HirType::Memory => "memory".to_string(),
        HirType::TypeDefinition { name }
        | HirType::Structure { name, .. }
        | HirType::Union { name, .. } => name.clone(),
    }
}

fn expression_type(expression: &HirExpression) -> HirType {
    match expression {
        HirExpression::Value(value) => value.ty(),
        HirExpression::Unary { ty, .. }
        | HirExpression::Binary { ty, .. }
        | HirExpression::Select { ty, .. }
        | HirExpression::Concat { ty, .. }
        | HirExpression::Extract { ty, .. }
        | HirExpression::Load { ty, .. }
        | HirExpression::Compare { ty, .. }
        | HirExpression::FloatCompare { ty, .. }
        | HirExpression::Cast { ty, .. }
        | HirExpression::Dereference { ty, .. }
        | HirExpression::Index { ty, .. }
        | HirExpression::AddressOf { ty, .. } => ty.clone(),
        HirExpression::Call { return_types, .. }
        | HirExpression::Intrinsic { return_types, .. } => {
            return_types.first().cloned().unwrap_or_else(HirType::void)
        }
    }
}

fn integer_bits(ty: &HirType) -> Option<u16> {
    match ty {
        HirType::Integer(bits) => Some(*bits),
        _ => None,
    }
}

fn extract_is_signbit(value: &HirExpression, lsb: u16) -> bool {
    integer_bits(&expression_type(value)).is_some_and(|bits| lsb + 1 == bits)
}

fn zero_value_expression(ty: &HirType) -> HirExpression {
    match ty {
        HirType::Integer(bits) => HirExpression::Value(HirValue::Integer {
            value: 0,
            bits: *bits,
        }),
        _ => HirExpression::Value(HirValue::Integer { value: 0, bits: 64 }),
    }
}

fn format_negated_expression(expression: &HirExpression) -> String {
    match expression {
        HirExpression::Extract { value, lsb, ty }
            if *ty == HirType::integer(1) && extract_is_signbit(value, *lsb) =>
        {
            let inner_ty = expression_type(value);
            format!(
                "{} >= {}",
                format_subexpression(value),
                format_expression(&zero_value_expression(&inner_ty))
            )
        }
        HirExpression::Unary {
            op: HirUnaryOperation::LogicalNot,
            value,
            ..
        } => format_expression(value),
        HirExpression::Compare { op, lhs, rhs, .. } => format!(
            "{} {} {}",
            format_subexpression(lhs),
            format_compare_op(invert_compare_for_print(*op)),
            format_subexpression(rhs)
        ),
        HirExpression::Binary { op, lhs, rhs, .. }
            if expression_type(lhs) == HirType::integer(1)
                && expression_type(rhs) == HirType::integer(1) =>
        {
            match op {
                HirBinaryOperation::Or => format!(
                    "{} && {}",
                    format_negated_subexpression(lhs),
                    format_negated_subexpression(rhs)
                ),
                HirBinaryOperation::And => format!(
                    "{} || {}",
                    format_negated_subexpression(lhs),
                    format_negated_subexpression(rhs)
                ),
                _ => format!("!{}", format_subexpression(expression)),
            }
        }
        _ => format!("!{}", format_subexpression(expression)),
    }
}

fn format_negated_subexpression(expression: &HirExpression) -> String {
    match expression {
        HirExpression::Compare { .. }
        | HirExpression::Unary {
            op: HirUnaryOperation::LogicalNot,
            ..
        }
        | HirExpression::Binary { .. }
        | HirExpression::Extract { .. } => format!("({})", format_negated_expression(expression)),
        _ => format_negated_expression(expression),
    }
}

fn format_address_space(space: &super::kind::HirAddressSpace) -> &'static str {
    match space {
        super::kind::HirAddressSpace::Default => "default",
        super::kind::HirAddressSpace::Stack => "stack",
        super::kind::HirAddressSpace::Heap => "heap",
        super::kind::HirAddressSpace::Global => "global",
        super::kind::HirAddressSpace::HeapObject { .. } => "heap_object",
        super::kind::HirAddressSpace::GlobalObject { .. } => "global_object",
        super::kind::HirAddressSpace::Io => "io",
        super::kind::HirAddressSpace::Local { .. } => "local",
        super::kind::HirAddressSpace::Argument { .. } => "argument",
        super::kind::HirAddressSpace::Spill { .. } => "spill",
        super::kind::HirAddressSpace::Incoming { .. } => "incoming",
        super::kind::HirAddressSpace::SavedFrame { .. } => "saved_frame",
        super::kind::HirAddressSpace::ReturnAddress { .. } => "return_address",
        super::kind::HirAddressSpace::Named { .. } => "named",
    }
}

fn format_code_location(name: &str) -> String {
    format!("@{}", name)
}

fn format_unary_op(op: HirUnaryOperation) -> &'static str {
    match op {
        HirUnaryOperation::LogicalNot => "!",
        HirUnaryOperation::BitNot => "~",
        HirUnaryOperation::Neg => "-",
        HirUnaryOperation::Popcount => "popcount ",
        HirUnaryOperation::CountLeadingZeros => "clz ",
        HirUnaryOperation::CountTrailingZeros => "ctz ",
    }
}

fn format_binary_op(op: HirBinaryOperation) -> &'static str {
    match op {
        HirBinaryOperation::Add => "+",
        HirBinaryOperation::Sub => "-",
        HirBinaryOperation::Mul => "*",
        HirBinaryOperation::FAdd => "+",
        HirBinaryOperation::FSub => "-",
        HirBinaryOperation::FMul => "*",
        HirBinaryOperation::FDiv => "/",
        HirBinaryOperation::And => "&",
        HirBinaryOperation::Or => "|",
        HirBinaryOperation::Xor => "^",
        HirBinaryOperation::Shl => "<<",
        HirBinaryOperation::LShr | HirBinaryOperation::AShr => ">>",
        HirBinaryOperation::UDiv | HirBinaryOperation::SDiv => "/",
        HirBinaryOperation::URem | HirBinaryOperation::SRem => "%",
        HirBinaryOperation::RotateLeft => "rol",
        HirBinaryOperation::RotateRight => "ror",
    }
}

fn format_binary_op_expression(op: HirBinaryOperation, expression: &HirExpression) -> &'static str {
    match (op, expression) {
        (HirBinaryOperation::And, HirExpression::Binary { ty, .. })
            if matches!(ty, HirType::Integer(1)) =>
        {
            "&&"
        }
        (HirBinaryOperation::Or, HirExpression::Binary { ty, .. })
            if matches!(ty, HirType::Integer(1)) =>
        {
            "||"
        }
        _ => format_binary_op(op),
    }
}

fn format_compare_op(op: HirCompareOperation) -> &'static str {
    match op {
        HirCompareOperation::Eq => "==",
        HirCompareOperation::Ne => "!=",
        HirCompareOperation::Ult | HirCompareOperation::Slt => "<",
        HirCompareOperation::Ule | HirCompareOperation::Sle => "<=",
        HirCompareOperation::Ugt | HirCompareOperation::Sgt => ">",
        HirCompareOperation::Uge | HirCompareOperation::Sge => ">=",
    }
}

fn invert_compare_for_print(op: HirCompareOperation) -> HirCompareOperation {
    match op {
        HirCompareOperation::Eq => HirCompareOperation::Ne,
        HirCompareOperation::Ne => HirCompareOperation::Eq,
        HirCompareOperation::Ult => HirCompareOperation::Uge,
        HirCompareOperation::Ule => HirCompareOperation::Ugt,
        HirCompareOperation::Ugt => HirCompareOperation::Ule,
        HirCompareOperation::Uge => HirCompareOperation::Ult,
        HirCompareOperation::Slt => HirCompareOperation::Sge,
        HirCompareOperation::Sle => HirCompareOperation::Sgt,
        HirCompareOperation::Sgt => HirCompareOperation::Sle,
        HirCompareOperation::Sge => HirCompareOperation::Slt,
    }
}

fn format_float_compare_op(op: HirFloatCompareOperation) -> &'static str {
    match op {
        HirFloatCompareOperation::Ordered => "ordered",
        HirFloatCompareOperation::Unordered => "unordered",
        HirFloatCompareOperation::Oeq => "oeq",
        HirFloatCompareOperation::One => "one",
        HirFloatCompareOperation::Olt => "olt",
        HirFloatCompareOperation::Ole => "ole",
        HirFloatCompareOperation::Ogt => "ogt",
        HirFloatCompareOperation::Oge => "oge",
        HirFloatCompareOperation::Ueq => "ueq",
        HirFloatCompareOperation::Une => "une",
        HirFloatCompareOperation::Ult => "ult",
        HirFloatCompareOperation::Ule => "ule",
        HirFloatCompareOperation::Ugt => "ugt",
        HirFloatCompareOperation::Uge => "uge",
    }
}

fn format_cast_op(op: HirCastOperation) -> &'static str {
    match op {
        HirCastOperation::ZeroExtend => "zext",
        HirCastOperation::SignExtend => "sext",
        HirCastOperation::Truncate => "trunc",
        HirCastOperation::Bitcast => "bitcast",
        HirCastOperation::IntToFloat => "sitofp",
        HirCastOperation::UIntToFloat => "uitofp",
        HirCastOperation::FloatToInt => "fptosi",
        HirCastOperation::FloatToUInt => "fptoui",
        HirCastOperation::FloatExtend => "fpext",
        HirCastOperation::FloatTruncate => "fptrunc",
    }
}

fn format_subexpression(expression: &HirExpression) -> String {
    match expression {
        HirExpression::Value(_)
        | HirExpression::Call { .. }
        | HirExpression::Intrinsic { .. }
        | HirExpression::AddressOf { .. }
        | HirExpression::Dereference { .. }
        | HirExpression::Index { .. }
        | HirExpression::Load { .. } => format_expression(expression),
        _ => format!("({})", format_expression(expression)),
    }
}

fn format_return_types(returns: &[HirType]) -> String {
    match returns.len() {
        0 => "void".to_string(),
        1 => format_type(&returns[0]),
        _ => format!(
            "({})",
            returns
                .iter()
                .map(format_type)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}
