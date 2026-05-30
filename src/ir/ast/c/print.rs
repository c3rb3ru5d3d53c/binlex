use crate::ir::ast::{
    AstBinaryOperation, AstBlock, AstCompareOperation, AstExpression, AstFloatCompareOperation,
    AstFunction, AstLocal, AstModule, AstPlace, AstStatement, AstTarget, AstType,
    AstUnaryOperation, AstValue,
};
use std::collections::{BTreeMap, BTreeSet};

pub fn format_c_module(module: &AstModule) -> String {
    module
        .functions
        .iter()
        .map(format_c_function)
        .collect::<Vec<_>>()
        .join("\n\n")
}

pub fn format_c_function(function: &AstFunction) -> String {
    let mut output = String::new();
    let context = CPrintContext::new(function);
    let returns = format_return_type(&function.returns);
    let name = sanitize_identifier(function.name.as_deref().unwrap_or("function"));
    let parameters = if function.parameters.is_empty() {
        "void".to_string()
    } else {
        function
            .parameters
            .iter()
            .map(|parameter| {
                format!(
                    "{} {}",
                    format_type(&parameter.ty),
                    sanitize_identifier(&parameter.name)
                )
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    output.push_str(&format!("{returns} {name}({parameters}) {{\n"));
    let mut declared = function
        .parameters
        .iter()
        .map(|parameter| parameter.name.clone())
        .collect::<BTreeSet<_>>();
    for local in &function.locals {
        declared.insert(local.name.clone());
        format_local_declaration_into(local, &context, &mut output);
        if let Some(init) = &local.init {
            output.push_str(" = ");
            output.push_str(&format_expression(init, &context));
        }
        output.push(';');
        if let Some(stack) = &local.stack {
            output.push_str(" // stack[");
            output.push_str(&format_stack_offset(stack.offset));
            output.push(']');
        }
        output.push('\n');
    }
    let mut implicit_locals = BTreeMap::new();
    for block in &function.blocks {
        collect_assigned_named_places(block, &mut implicit_locals);
    }
    for (name, ty) in implicit_locals {
        if declared.contains(&name) {
            continue;
        }
        declared.insert(name.clone());
        output.push_str("    ");
        output.push_str(&format_type(&ty));
        output.push(' ');
        output.push_str(&context.local_name(&name));
        output.push_str(";\n");
    }
    if !declared.is_empty() && !function.blocks.is_empty() {
        output.push('\n');
    }
    for block in &function.blocks {
        format_block_into(block, 1, &context, &mut output);
    }
    output.push('}');
    output
}

struct CPrintContext {
    local_names: BTreeMap<String, String>,
}

impl CPrintContext {
    fn new(function: &AstFunction) -> Self {
        let mut local_names = BTreeMap::new();
        let mut index = 0usize;
        for local in &function.locals {
            if !local_names.contains_key(&local.name) {
                local_names.insert(local.name.clone(), format!("v{index}"));
                index += 1;
            }
        }
        let mut implicit_locals = BTreeMap::new();
        for block in &function.blocks {
            collect_assigned_named_places(block, &mut implicit_locals);
        }
        for name in implicit_locals.keys() {
            if function
                .parameters
                .iter()
                .any(|parameter| parameter.name == *name)
            {
                continue;
            }
            if !local_names.contains_key(name) {
                local_names.insert(name.clone(), format!("v{index}"));
                index += 1;
            }
        }
        Self { local_names }
    }

    fn local_name(&self, name: &str) -> String {
        self.local_names
            .get(name)
            .cloned()
            .unwrap_or_else(|| sanitize_identifier(name))
    }
}

fn format_local_declaration_into(local: &AstLocal, context: &CPrintContext, output: &mut String) {
    output.push_str("    ");
    output.push_str(&format_type(&local.ty));
    output.push(' ');
    output.push_str(&context.local_name(&local.name));
}

fn format_block_into(
    block: &AstBlock,
    indent: usize,
    context: &CPrintContext,
    output: &mut String,
) {
    for statement in &block.statements {
        format_statement_into(statement, indent, context, output);
    }
}

fn format_statement_into(
    statement: &AstStatement,
    indent: usize,
    context: &CPrintContext,
    output: &mut String,
) {
    let pad = "    ".repeat(indent);
    match statement {
        AstStatement::Assign { target, value } => {
            output.push_str(&pad);
            output.push_str(&format_place(target, context));
            output.push_str(" = ");
            output.push_str(&format_expression(value, context));
            output.push(';');
            if let Some(comment) = expression_symbol_comment(value) {
                output.push_str(" /* ");
                output.push_str(comment);
                output.push_str(" */");
            }
            output.push('\n');
        }
        AstStatement::Expr(value) => {
            output.push_str(&pad);
            output.push_str(&format_expression(value, context));
            output.push(';');
            if let Some(comment) = expression_symbol_comment(value) {
                output.push_str(" /* ");
                output.push_str(comment);
                output.push_str(" */");
            }
            output.push('\n');
        }
        AstStatement::If {
            condition,
            then_body,
            else_body,
        } => {
            output.push_str(&pad);
            output.push_str("if (");
            output.push_str(&format_expression(condition, context));
            output.push_str(") {\n");
            format_block_into(then_body, indent + 1, context, output);
            output.push_str(&pad);
            output.push('}');
            if let Some(else_body) = else_body {
                output.push_str(" else {\n");
                format_block_into(else_body, indent + 1, context, output);
                output.push_str(&pad);
                output.push('}');
            }
            output.push('\n');
        }
        AstStatement::While { condition, body } => {
            output.push_str(&pad);
            output.push_str("while (");
            output.push_str(&format_expression(condition, context));
            output.push_str(") {\n");
            format_block_into(body, indent + 1, context, output);
            output.push_str(&pad);
            output.push_str("}\n");
        }
        AstStatement::Loop { body } => {
            output.push_str(&pad);
            output.push_str("while (1) {\n");
            format_block_into(body, indent + 1, context, output);
            output.push_str(&pad);
            output.push_str("}\n");
        }
        AstStatement::Switch {
            value,
            cases,
            default,
        } => {
            output.push_str(&pad);
            output.push_str("switch (");
            output.push_str(&format_expression(value, context));
            output.push_str(") {\n");
            for case in cases {
                output.push_str(&pad);
                output.push_str("case ");
                output.push_str(&format_value(&case.value, context));
                output.push_str(":\n");
                format_block_into(&case.body, indent + 1, context, output);
            }
            if let Some(default) = default {
                output.push_str(&pad);
                output.push_str("default:\n");
                format_block_into(default, indent + 1, context, output);
            }
            output.push_str(&pad);
            output.push_str("}\n");
        }
        AstStatement::Break => {
            output.push_str(&pad);
            output.push_str("break;\n");
        }
        AstStatement::Continue => {
            output.push_str(&pad);
            output.push_str("continue;\n");
        }
        AstStatement::Return { values } => {
            output.push_str(&pad);
            if values.is_empty() {
                output.push_str("return;\n");
            } else {
                output.push_str("return ");
                output.push_str(
                    &values
                        .iter()
                        .map(|value| format_expression(value, context))
                        .collect::<Vec<_>>()
                        .join(", "),
                );
                output.push_str(";\n");
            }
        }
        AstStatement::Label(label) => {
            output.push_str(label);
            output.push_str(":\n");
        }
        AstStatement::Goto(target) => {
            output.push_str(&pad);
            output.push_str("goto ");
            output.push_str(&format_target(target, context));
            output.push_str(";\n");
        }
        AstStatement::Trap => {
            output.push_str(&pad);
            output.push_str("__builtin_trap();\n");
        }
        AstStatement::Unreachable => {
            output.push_str(&pad);
            output.push_str("__builtin_unreachable();\n");
        }
    }
}

fn format_expression(expression: &AstExpression, context: &CPrintContext) -> String {
    match expression {
        AstExpression::Value(value) => format_value(value, context),
        AstExpression::Unary { op, value, .. } => {
            format!(
                "{}{}",
                format_unary_op(*op),
                format_subexpression(value, context)
            )
        }
        AstExpression::Binary { op, lhs, rhs, .. } => format!(
            "{} {} {}",
            format_subexpression(lhs, context),
            format_binary_op(*op),
            format_subexpression(rhs, context)
        ),
        AstExpression::Select {
            condition,
            when_true,
            when_false,
            ..
        } => format!(
            "{} ? {} : {}",
            format_subexpression(condition, context),
            format_subexpression(when_true, context),
            format_subexpression(when_false, context)
        ),
        AstExpression::Concat { parts, .. } => format!(
            "CONCAT({})",
            parts
                .iter()
                .map(|part| format_expression(part, context))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        AstExpression::Extract { value, lsb, ty } => {
            let bits = integer_bits(ty).unwrap_or(64);
            let mask = if bits >= 128 {
                u128::MAX
            } else {
                (1u128 << bits) - 1
            };
            format!(
                "(({} >> {}) & {:#x})",
                format_subexpression(value, context),
                lsb,
                mask
            )
        }
        AstExpression::Load { address, ty, .. } => {
            format!(
                "*({}*){}",
                format_type(ty),
                format_subexpression(address, context)
            )
        }
        AstExpression::Compare { op, lhs, rhs, .. } => format!(
            "{} {} {}",
            format_subexpression(lhs, context),
            format_compare_op(*op),
            format_subexpression(rhs, context)
        ),
        AstExpression::FloatCompare { op, lhs, rhs, .. } => format!(
            "{} {} {}",
            format_subexpression(lhs, context),
            format_float_compare_op(*op),
            format_subexpression(rhs, context)
        ),
        AstExpression::Cast { value, ty, .. } => {
            format!(
                "({}){}",
                format_type(ty),
                format_subexpression(value, context)
            )
        }
        AstExpression::Call {
            target, arguments, ..
        } => format!(
            "{}({})",
            format_call_target(target, context),
            arguments
                .iter()
                .map(|argument| format_expression(argument, context))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        AstExpression::Intrinsic {
            name, arguments, ..
        } => format!(
            "{}({})",
            sanitize_identifier(name),
            arguments
                .iter()
                .map(|argument| format_expression(argument, context))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        AstExpression::AddressOf { place, .. } => format!("&{}", format_place(place, context)),
        AstExpression::Deref { pointer, ty } => {
            format!(
                "*({}*){}",
                format_type(ty),
                format_subexpression(pointer, context)
            )
        }
        AstExpression::Index { base, index, .. } => {
            format!(
                "{}[{}]",
                format_subexpression(base, context),
                format_expression(index, context)
            )
        }
    }
}

fn format_subexpression(expression: &AstExpression, context: &CPrintContext) -> String {
    match expression {
        AstExpression::Value(_)
        | AstExpression::Call { .. }
        | AstExpression::Intrinsic { .. }
        | AstExpression::Load { .. }
        | AstExpression::Deref { .. }
        | AstExpression::Index { .. } => format_expression(expression, context),
        _ => format!("({})", format_expression(expression, context)),
    }
}

fn format_place(place: &AstPlace, context: &CPrintContext) -> String {
    match place {
        AstPlace::Named { name, .. } => context.local_name(name),
        AstPlace::Deref { pointer, ty } => {
            format!(
                "*({}*){}",
                format_type(ty),
                format_subexpression(pointer, context)
            )
        }
        AstPlace::Memory { address, ty, .. } => {
            format!(
                "*({}*){}",
                format_type(ty),
                format_subexpression(address, context)
            )
        }
        AstPlace::Index { base, index, .. } => {
            format!(
                "{}[{}]",
                format_subexpression(base, context),
                format_expression(index, context)
            )
        }
    }
}

fn format_target(target: &AstTarget, context: &CPrintContext) -> String {
    match target {
        AstTarget::Direct(name) => sanitize_identifier(name),
        AstTarget::Indirect(expression) => {
            format!("*{}", format_subexpression(expression, context))
        }
    }
}

fn format_call_target(target: &AstTarget, context: &CPrintContext) -> String {
    match target {
        AstTarget::Direct(name) => sanitize_identifier(display_symbol_name(name)),
        AstTarget::Indirect(expression) => format!("(*{})", format_expression(expression, context)),
    }
}

fn expression_symbol_comment(expression: &AstExpression) -> Option<&str> {
    match expression {
        AstExpression::Call {
            target: AstTarget::Direct(name),
            ..
        } => symbol_comment(name),
        _ => None,
    }
}

fn display_symbol_name(name: &str) -> &str {
    name.rsplit_once('!')
        .map(|(_, symbol)| symbol)
        .unwrap_or(name)
}

fn symbol_comment(name: &str) -> Option<&str> {
    name.contains('!').then_some(name)
}

fn format_value(value: &AstValue, context: &CPrintContext) -> String {
    match value {
        AstValue::Named { name, .. } => context.local_name(name),
        AstValue::Integer { value, bits } => {
            format!("{value}{suffix}", suffix = integer_suffix(*bits))
        }
        AstValue::Boolean(value) => {
            if *value {
                "1".to_string()
            } else {
                "0".to_string()
            }
        }
        AstValue::Null { .. } => "NULL".to_string(),
        AstValue::Undef { ty } => format_undef_value(ty),
    }
}

fn collect_assigned_named_places(block: &AstBlock, locals: &mut BTreeMap<String, AstType>) {
    for statement in &block.statements {
        collect_assigned_named_places_in_statement(statement, locals);
    }
}

fn collect_assigned_named_places_in_statement(
    statement: &AstStatement,
    locals: &mut BTreeMap<String, AstType>,
) {
    match statement {
        AstStatement::Assign {
            target: AstPlace::Named { name, ty },
            ..
        } => {
            locals.entry(name.clone()).or_insert_with(|| ty.clone());
        }
        AstStatement::If {
            then_body,
            else_body,
            ..
        } => {
            collect_assigned_named_places(then_body, locals);
            if let Some(else_body) = else_body {
                collect_assigned_named_places(else_body, locals);
            }
        }
        AstStatement::While { body, .. } | AstStatement::Loop { body } => {
            collect_assigned_named_places(body, locals);
        }
        AstStatement::Switch { cases, default, .. } => {
            for case in cases {
                collect_assigned_named_places(&case.body, locals);
            }
            if let Some(default) = default {
                collect_assigned_named_places(default, locals);
            }
        }
        AstStatement::Assign { .. }
        | AstStatement::Expr(_)
        | AstStatement::Break
        | AstStatement::Continue
        | AstStatement::Return { .. }
        | AstStatement::Label(_)
        | AstStatement::Goto(_)
        | AstStatement::Trap
        | AstStatement::Unreachable => {}
    }
}

fn format_undef_value(ty: &AstType) -> String {
    match ty {
        AstType::Integer(bits) if *bits >= 64 => "0ULL".to_string(),
        AstType::Integer(_) => "0".to_string(),
        AstType::Float(_) => "0.0".to_string(),
        AstType::Pointer { .. } | AstType::Memory | AstType::Function { .. } => "NULL".to_string(),
        AstType::Void | AstType::Custom { .. } => "0".to_string(),
    }
}

fn format_return_type(returns: &[AstType]) -> String {
    match returns {
        [] => "void".to_string(),
        [ty] => format_type(ty),
        _ => "/* multi-return */ void".to_string(),
    }
}

fn format_type(ty: &AstType) -> String {
    match ty {
        AstType::Void => "void".to_string(),
        AstType::Integer(bits) => format!("uint{bits}_t"),
        AstType::Float(32) => "float".to_string(),
        AstType::Float(64) => "double".to_string(),
        AstType::Float(bits) => format!("float{bits}_t"),
        AstType::Pointer { pointee } => format!("{}*", format_type(pointee)),
        AstType::Function { .. } => "void*".to_string(),
        AstType::Memory => "uint8_t*".to_string(),
        AstType::Custom { name } => sanitize_identifier(name),
    }
}

fn format_stack_offset(offset: i64) -> String {
    if offset < 0 {
        format!("-0x{:x}", offset.unsigned_abs())
    } else {
        format!("+0x{:x}", offset)
    }
}

fn integer_bits(ty: &AstType) -> Option<u16> {
    if let AstType::Integer(bits) = ty {
        Some(*bits)
    } else {
        None
    }
}

fn integer_suffix(bits: u16) -> &'static str {
    match bits {
        64 => "ULL",
        _ => "",
    }
}

fn format_unary_op(op: AstUnaryOperation) -> &'static str {
    match op {
        AstUnaryOperation::LogicalNot => "!",
        AstUnaryOperation::BitNot => "~",
        AstUnaryOperation::Neg => "-",
        AstUnaryOperation::Popcount => "__builtin_popcount",
        AstUnaryOperation::CountLeadingZeros => "__builtin_clz",
        AstUnaryOperation::CountTrailingZeros => "__builtin_ctz",
    }
}

fn format_binary_op(op: AstBinaryOperation) -> &'static str {
    match op {
        AstBinaryOperation::Add | AstBinaryOperation::FAdd => "+",
        AstBinaryOperation::Sub | AstBinaryOperation::FSub => "-",
        AstBinaryOperation::Mul | AstBinaryOperation::FMul => "*",
        AstBinaryOperation::FDiv | AstBinaryOperation::UDiv | AstBinaryOperation::SDiv => "/",
        AstBinaryOperation::And => "&",
        AstBinaryOperation::Or => "|",
        AstBinaryOperation::Xor => "^",
        AstBinaryOperation::Shl => "<<",
        AstBinaryOperation::LShr | AstBinaryOperation::AShr => ">>",
        AstBinaryOperation::URem | AstBinaryOperation::SRem => "%",
        AstBinaryOperation::RotateLeft => "ROTL",
        AstBinaryOperation::RotateRight => "ROTR",
    }
}

fn format_compare_op(op: AstCompareOperation) -> &'static str {
    match op {
        AstCompareOperation::Eq => "==",
        AstCompareOperation::Ne => "!=",
        AstCompareOperation::Ult | AstCompareOperation::Slt => "<",
        AstCompareOperation::Ule | AstCompareOperation::Sle => "<=",
        AstCompareOperation::Ugt | AstCompareOperation::Sgt => ">",
        AstCompareOperation::Uge | AstCompareOperation::Sge => ">=",
    }
}

fn format_float_compare_op(op: AstFloatCompareOperation) -> &'static str {
    match op {
        AstFloatCompareOperation::Oeq | AstFloatCompareOperation::Ueq => "==",
        AstFloatCompareOperation::One | AstFloatCompareOperation::Une => "!=",
        AstFloatCompareOperation::Olt | AstFloatCompareOperation::Ult => "<",
        AstFloatCompareOperation::Ole | AstFloatCompareOperation::Ule => "<=",
        AstFloatCompareOperation::Ogt | AstFloatCompareOperation::Ugt => ">",
        AstFloatCompareOperation::Oge | AstFloatCompareOperation::Uge => ">=",
        AstFloatCompareOperation::Ordered => "/* ordered */ ==",
        AstFloatCompareOperation::Unordered => "/* unordered */ !=",
    }
}

fn sanitize_identifier(name: &str) -> String {
    let mut result = String::with_capacity(name.len());
    for (index, c) in name.chars().enumerate() {
        if c.is_ascii_alphanumeric() || c == '_' {
            if index == 0 && c.is_ascii_digit() {
                result.push('_');
            }
            result.push(c);
        } else {
            result.push('_');
        }
    }
    if result.is_empty() {
        "_".to_string()
    } else {
        result
    }
}
