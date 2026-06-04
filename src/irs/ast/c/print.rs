use crate::formats::{Image, VirtualImage};
use crate::irs::ast::{
    AstAddressSpace, AstBinaryOperation, AstBlock, AstCompareOperation, AstExpression,
    AstFloatCompareOperation, AstFunction, AstLocal, AstModule, AstPlace, AstStatement, AstTarget,
    AstType, AstUnaryOperation, AstValue,
};
use crate::irs::lir::LirAbi;
use crate::irs::storage::IrStorage;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

const MAX_STRING_BYTES: usize = 512;
const MIN_STRING_CHARS: usize = 4;
const MAX_C_LINE_LEN: usize = 100;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StringPreference {
    Any,
    Ascii,
    WideModule,
}

pub fn format_c_module(module: &AstModule) -> String {
    module
        .functions
        .iter()
        .map(format_c_function)
        .collect::<Vec<_>>()
        .join("\n\n")
}

pub fn format_c_function(function: &AstFunction) -> String {
    format_c_function_inner_virtual(
        function,
        function
            .image
            .as_ref()
            .map(|image| image as &dyn VirtualImage),
    )
}

pub fn format_c_function_with_image(function: &AstFunction, image: &Image) -> String {
    format_c_function_inner_virtual(function, Some(image as &dyn VirtualImage))
}

fn format_c_function_inner_virtual(
    function: &AstFunction,
    image: Option<&dyn VirtualImage>,
) -> String {
    let mut output = String::new();
    let context = CPrintContext::new(function, image);
    if let Some(comment) = &function.comment {
        output.push_str("// ");
        output.push_str(&format_comment_text(comment));
        output.push('\n');
    }
    let returns = format_return_type(&function.returns);
    let convention = format_abi_calling_convention(function.abi.as_ref());
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
    let header = format!("{returns}{convention} {name}({parameters}) {{\n");
    if header.trim_end().chars().count() > MAX_C_LINE_LEN && !function.parameters.is_empty() {
        output.push_str(&format!("{returns}{convention} {name}(\n"));
        for (index, parameter) in function.parameters.iter().enumerate() {
            output.push_str("    ");
            output.push_str(&format_type(&parameter.ty));
            output.push(' ');
            output.push_str(&sanitize_identifier(&parameter.name));
            if index + 1 != function.parameters.len() {
                output.push(',');
            }
            output.push('\n');
        }
        output.push_str(") {\n");
    } else {
        output.push_str(&header);
    }
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
        let mut comments = Vec::new();
        if let Some(storage) = &local.storage
            && let Some(comment) = format_storage(storage, &local.ty)
        {
            comments.push(comment);
        }
        if let Some(comment) = &local.comment {
            comments.push(format_comment_text(comment));
        }
        if !comments.is_empty() {
            output.push_str(" // ");
            output.push_str(&comments.join("; "));
        }
        output.push('\n');
    }
    let mut implicit_locals = BTreeMap::new();
    for block in &function.blocks {
        collect_assigned_named_places(block, &mut implicit_locals);
        collect_referenced_named_values(block, &mut implicit_locals);
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
    for local in &context.synthetic_stack_locals {
        output.push_str("    ");
        output.push_str(&format_type(&local.ty));
        output.push(' ');
        output.push_str(&local.name);
        output.push_str("; // ");
        output.push_str(&format_stack_address_comment(
            &local.base,
            i128::from(local.offset),
        ));
        output.push('\n');
    }
    if (!declared.is_empty() || !context.synthetic_stack_locals.is_empty())
        && !function.blocks.is_empty()
    {
        output.push('\n');
    }
    for block in &function.blocks {
        format_block_into(block, 1, &context, &mut output);
    }
    output.push('}');
    output
}

struct CPrintContext<'a> {
    local_names: BTreeMap<String, String>,
    stack_locals: BTreeMap<(String, i64), String>,
    local_stack_locations: BTreeMap<String, (String, i64)>,
    register_locals: BTreeMap<String, String>,
    synthetic_stack_locals: Vec<SyntheticStackLocal>,
    rip_locals: BTreeSet<String>,
    entry_address: Option<u64>,
    image: Option<&'a dyn VirtualImage>,
    string_cache: RefCell<BTreeMap<u64, Option<String>>>,
    suppressed_stack_local_load: RefCell<Option<(String, i64)>>,
}

struct SyntheticStackLocal {
    name: String,
    ty: AstType,
    base: String,
    offset: i64,
}

impl<'a> CPrintContext<'a> {
    fn new(function: &AstFunction, image: Option<&'a dyn VirtualImage>) -> Self {
        let mut local_names = BTreeMap::new();
        let mut index = 0usize;
        for local in &function.locals {
            if !local_names.contains_key(&local.name) {
                let name = local
                    .display_name
                    .as_deref()
                    .map(sanitize_identifier)
                    .unwrap_or_else(|| format!("v{index}"));
                local_names.insert(local.name.clone(), name);
                index += 1;
            }
        }
        let mut implicit_locals = BTreeMap::new();
        for block in &function.blocks {
            collect_assigned_named_places(block, &mut implicit_locals);
            collect_referenced_named_values(block, &mut implicit_locals);
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
        let mut stack_locals = BTreeMap::new();
        let mut local_stack_locations = BTreeMap::new();
        for local in &function.locals {
            if let Some(IrStorage::Stack { base, offset, .. }) = &local.storage {
                local_stack_locations.insert(local.name.clone(), (base.clone(), *offset));
                stack_locals
                    .entry((base.clone(), *offset))
                    .or_insert_with(|| local_names[&local.name].clone());
            }
        }
        let mut synthetic_stack_slots = BTreeMap::new();
        for block in &function.blocks {
            collect_stack_memory_slots(block, &mut synthetic_stack_slots);
        }
        let mut synthetic_stack_locals = Vec::new();
        for ((base, offset), ty) in synthetic_stack_slots {
            if stack_locals.contains_key(&(base.clone(), offset)) {
                continue;
            }
            let name = format!("v{index}");
            index += 1;
            stack_locals.insert((base.clone(), offset), name.clone());
            synthetic_stack_locals.push(SyntheticStackLocal {
                name,
                ty,
                base,
                offset,
            });
        }
        let rip_locals = function
            .locals
            .iter()
            .filter_map(|local| match &local.storage {
                Some(IrStorage::Register { name, .. })
                    if matches!(name.as_str(), "rip" | "eip" | "pc") =>
                {
                    Some(local.name.clone())
                }
                _ => None,
            })
            .collect();
        let register_locals = function
            .locals
            .iter()
            .filter_map(|local| match &local.storage {
                Some(IrStorage::Register { name, .. }) => {
                    Some((name.clone(), local_names[&local.name].clone()))
                }
                _ => None,
            })
            .collect();
        let entry_address = function.name.as_deref().and_then(parse_function_address);
        Self {
            local_names,
            stack_locals,
            local_stack_locations,
            register_locals,
            synthetic_stack_locals,
            rip_locals,
            entry_address,
            image,
            string_cache: RefCell::new(BTreeMap::new()),
            suppressed_stack_local_load: RefCell::new(None),
        }
    }

    fn local_name(&self, name: &str) -> String {
        self.local_names
            .get(name)
            .cloned()
            .unwrap_or_else(|| sanitize_identifier(name))
    }

    fn stack_local_name(&self, base: &str, offset: i64) -> Option<String> {
        self.stack_locals.get(&(base.to_string(), offset)).cloned()
    }

    fn local_stack_location(&self, name: &str) -> Option<(String, i64)> {
        self.local_stack_locations.get(name).cloned()
    }

    fn register_local_name(&self, name: &str) -> Option<&str> {
        self.register_locals.get(name).map(String::as_str)
    }

    fn string_literal(&self, address: u64) -> Option<String> {
        self.image?;
        if let Some(cached) = self.string_cache.borrow().get(&address) {
            return cached.clone();
        }
        let literal = self.resolve_string_literal(address);
        self.string_cache
            .borrow_mut()
            .insert(address, literal.clone());
        literal
    }

    fn resolve_string_literal(&self, address: u64) -> Option<String> {
        let image = self.image?;
        let bytes = image
            .read_virtual_bytes(address, MAX_STRING_BYTES)
            .ok()
            .flatten()?;
        decode_wide_string_literal(&bytes).or_else(|| decode_ascii_string_literal(&bytes))
    }

    fn normalized_string_literal(&self, address: u64) -> Option<String> {
        self.backward_wide_component_string_literal(address, 0x100)
            .or_else(|| self.backward_ascii_component_string_literal(address, 0x100))
            .or_else(|| self.string_literal(address))
            .or_else(|| {
                address
                    .checked_sub(1)
                    .and_then(|address| self.string_literal(address))
            })
            .or_else(|| {
                address
                    .checked_add(1)
                    .and_then(|address| self.string_literal(address))
            })
    }

    fn expression_string_literal(&self, expression: &AstExpression) -> Option<String> {
        self.expression_string_literal_with_preference(expression, StringPreference::Any)
    }

    fn expression_string_literal_with_preference(
        &self,
        expression: &AstExpression,
        preference: StringPreference,
    ) -> Option<String> {
        if let AstExpression::Value(AstValue::Integer { value, bits }) = expression
            && *bits >= 32
            && let Ok(address) = u64::try_from(*value)
        {
            return self
                .normalized_string_literal(address)
                .filter(|literal| string_literal_matches_preference(literal, preference));
        }
        let address = self.resolve_expression_address(expression)?;
        self.normalized_string_literal(address)
            .filter(|literal| string_literal_matches_preference(literal, preference))
            .or_else(|| self.scan_forward_string_literal_with_preference(address, 0x80, preference))
    }

    fn backward_wide_component_string_literal(
        &self,
        address: u64,
        max_scan: u64,
    ) -> Option<String> {
        let mut start = if address % 2 == 0 {
            address
        } else {
            address.checked_sub(1)?
        };
        if start < 2 || !self.previous_wide_unit_is_interior(start)? {
            return None;
        };
        let lower_bound = address.saturating_sub(max_scan);
        while start >= lower_bound + 2 {
            let previous = start - 2;
            let bytes = self.image?.read_virtual_bytes(previous, 2).ok().flatten()?;
            if bytes.len() != 2 || bytes == [0, 0] || is_utf16_path_separator(&bytes) {
                break;
            }
            if !is_likely_utf16_unit(&bytes) {
                return None;
            }
            start = previous;
        }
        (start != address)
            .then(|| self.string_literal(start))
            .flatten()
    }

    fn previous_wide_unit_is_interior(&self, address: u64) -> Option<bool> {
        let previous = address.checked_sub(2)?;
        let bytes = self.image?.read_virtual_bytes(previous, 2).ok().flatten()?;
        Some(bytes.len() == 2 && bytes != [0, 0] && !is_utf16_path_separator(&bytes))
    }

    fn backward_ascii_component_string_literal(
        &self,
        address: u64,
        max_scan: u64,
    ) -> Option<String> {
        if !self.previous_ascii_byte_is_interior(address)? {
            return None;
        }
        let mut start = address;
        let lower_bound = address.saturating_sub(max_scan);
        while start > lower_bound {
            let previous = start - 1;
            let bytes = self.image?.read_virtual_bytes(previous, 1).ok().flatten()?;
            if bytes
                .first()
                .is_none_or(|byte| *byte == 0 || *byte == b'\\' || *byte == b'/')
            {
                break;
            }
            if !is_ascii_string_byte(bytes[0]) {
                return None;
            }
            start = previous;
        }
        (start != address)
            .then(|| self.string_literal(start))
            .flatten()
    }

    fn previous_ascii_byte_is_interior(&self, address: u64) -> Option<bool> {
        let previous = address.checked_sub(1)?;
        let bytes = self.image?.read_virtual_bytes(previous, 1).ok().flatten()?;
        Some(bytes.first().is_some_and(|byte| {
            *byte != 0 && *byte != b'\\' && *byte != b'/' && is_ascii_string_byte(*byte)
        }))
    }

    fn scan_forward_string_literal_with_preference(
        &self,
        address: u64,
        max_scan: u64,
        preference: StringPreference,
    ) -> Option<String> {
        (1..=max_scan)
            .filter_map(|offset| address.checked_add(offset))
            .find_map(|candidate| {
                self.string_literal(candidate)
                    .filter(|literal| string_literal_matches_preference(literal, preference))
            })
    }

    fn resolve_expression_address(&self, expression: &AstExpression) -> Option<u64> {
        let AstExpression::Binary { op, lhs, rhs, .. } = expression else {
            return None;
        };
        if !matches!(op, AstBinaryOperation::Add) {
            return None;
        }
        let displacement = match (
            self.expression_is_rip(lhs),
            self.expression_integer(rhs),
            self.expression_is_rip(rhs),
            self.expression_integer(lhs),
        ) {
            (true, Some(displacement), _, _) | (_, _, true, Some(displacement)) => displacement,
            _ => return None,
        };
        let entry = self.entry_address?;
        if displacement >= 0 {
            entry.checked_add(displacement as u64)
        } else {
            entry.checked_sub(displacement.unsigned_abs() as u64)
        }
    }

    fn expression_integer(&self, expression: &AstExpression) -> Option<i128> {
        match expression {
            AstExpression::Value(AstValue::Integer { value, .. }) => Some(*value),
            _ => None,
        }
    }

    fn expression_is_rip(&self, expression: &AstExpression) -> bool {
        matches!(
            expression,
            AstExpression::Value(AstValue::Named { name, .. }) if self.rip_locals.contains(name)
        )
    }
}

fn format_local_declaration_into(
    local: &AstLocal,
    context: &CPrintContext<'_>,
    output: &mut String,
) {
    output.push_str("    ");
    output.push_str(&format_type(&local.ty));
    output.push(' ');
    output.push_str(&context.local_name(&local.name));
}

fn format_block_into(
    block: &AstBlock,
    indent: usize,
    context: &CPrintContext<'_>,
    output: &mut String,
) {
    for statement in &block.statements {
        format_statement_into(statement, indent, context, output);
    }
}

fn format_statement_into(
    statement: &AstStatement,
    indent: usize,
    context: &CPrintContext<'_>,
    output: &mut String,
) {
    let pad = "    ".repeat(indent);
    match statement {
        AstStatement::Comment(comment) => {
            output.push_str(&pad);
            output.push_str("// ");
            output.push_str(&format_comment_text(comment));
            output.push('\n');
        }
        AstStatement::Assign { target, value } => {
            if let Some(segment_store) = format_segment_store(target, value, context) {
                output.push_str(&pad);
                output.push_str(&segment_store);
                output.push(';');
                output.push('\n');
                return;
            }
            if matches!(target, AstPlace::Named { .. })
                && !expression_has_c_side_effects(value)
                && format_place(target, context) == format_expression(value, context)
            {
                return;
            }
            let target_text = format_place(target, context);
            let suppressed_stack_local = place_stack_location(target, context);
            let previous_suppression = context
                .suppressed_stack_local_load
                .replace(suppressed_stack_local);
            let value_text = format_expression(value, context);
            context
                .suppressed_stack_local_load
                .replace(previous_suppression);
            let line = format!("{pad}{target_text} = {value_text};");
            if line.chars().count() > MAX_C_LINE_LEN
                && let Some(wrapped) =
                    format_call_statement_lines(Some(&target_text), value, indent, context)
            {
                output.push_str(&wrapped);
            } else if line.chars().count() > MAX_C_LINE_LEN
                && let Some(wrapped) =
                    format_binary_assignment_lines(&target_text, value, indent, context)
            {
                output.push_str(&wrapped);
            } else {
                output.push_str(&line);
                output.push('\n');
            }
        }
        AstStatement::Expr(value) => {
            let line = format!("{pad}{};", format_expression(value, context));
            if line.chars().count() > MAX_C_LINE_LEN
                && let Some(wrapped) = format_call_statement_lines(None, value, indent, context)
            {
                output.push_str(&wrapped);
            } else {
                output.push_str(&line);
                output.push('\n');
            }
        }
        AstStatement::If {
            condition,
            then_body,
            else_body,
        } => {
            let condition_text = format_condition(condition, context);
            output.push_str(&format_control_header(
                "if",
                condition,
                &condition_text,
                indent,
                context,
            ));
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
            let condition_text = format_condition(condition, context);
            output.push_str(&format_control_header(
                "while",
                condition,
                &condition_text,
                indent,
                context,
            ));
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

fn format_call_statement_lines(
    assignment_target: Option<&str>,
    expression: &AstExpression,
    indent: usize,
    context: &CPrintContext<'_>,
) -> Option<String> {
    let (callee, arguments) = match expression {
        AstExpression::Call {
            target,
            abi,
            arguments,
            return_types,
        } => (
            format_call_target(target, abi.as_ref(), return_types, arguments, context),
            arguments
                .iter()
                .enumerate()
                .map(|(index, argument)| format_call_argument(target, index, argument, context))
                .collect::<Vec<_>>(),
        ),
        AstExpression::Intrinsic {
            name, arguments, ..
        } => (
            sanitize_identifier(name),
            arguments
                .iter()
                .map(|argument| format_expression(argument, context))
                .collect::<Vec<_>>(),
        ),
        _ => return None,
    };

    let pad = "    ".repeat(indent);
    let arg_pad = "    ".repeat(indent + 1);
    let mut output = String::new();
    output.push_str(&pad);
    if let Some(target) = assignment_target {
        output.push_str(target);
        output.push_str(" = ");
    }
    output.push_str(&callee);
    output.push_str("(\n");
    for (index, argument) in arguments.iter().enumerate() {
        output.push_str(&arg_pad);
        output.push_str(argument);
        if index + 1 != arguments.len() {
            output.push(',');
        }
        output.push('\n');
    }
    output.push_str(&pad);
    output.push_str(");");
    output.push('\n');
    Some(output)
}

fn format_binary_assignment_lines(
    target: &str,
    expression: &AstExpression,
    indent: usize,
    context: &CPrintContext<'_>,
) -> Option<String> {
    let mut terms = Vec::new();
    collect_additive_terms(expression, context, &mut terms);
    if terms.len() < 2 {
        return None;
    }

    let pad = "    ".repeat(indent);
    let continuation_pad = "    ".repeat(indent + 1);
    let mut output = String::new();
    output.push_str(&pad);
    output.push_str(target);
    output.push_str(" = ");
    output.push_str(&terms[0].1);
    output.push('\n');
    for (index, (op, value)) in terms.iter().enumerate().skip(1) {
        output.push_str(&continuation_pad);
        output.push_str(op);
        output.push(' ');
        output.push_str(value);
        if index + 1 == terms.len() {
            output.push(';');
        }
        output.push('\n');
    }
    Some(output)
}

fn collect_additive_terms(
    expression: &AstExpression,
    context: &CPrintContext<'_>,
    terms: &mut Vec<(&'static str, String)>,
) {
    match expression {
        AstExpression::Binary {
            op: AstBinaryOperation::Add,
            lhs,
            rhs,
            ..
        } => {
            collect_additive_terms(lhs, context, terms);
            terms.push(("+", format_subexpression_inner(rhs, context, false)));
        }
        AstExpression::Binary {
            op: AstBinaryOperation::Sub,
            lhs,
            rhs,
            ..
        } => {
            collect_additive_terms(lhs, context, terms);
            terms.push(("-", format_subexpression_inner(rhs, context, false)));
        }
        expression => terms.push(("", format_expression(expression, context))),
    }
}

fn format_control_header(
    keyword: &str,
    condition: &AstExpression,
    condition_text: &str,
    indent: usize,
    context: &CPrintContext<'_>,
) -> String {
    let pad = "    ".repeat(indent);
    let line = format!("{pad}{keyword} ({condition_text}) {{\n");
    if line.chars().count() <= MAX_C_LINE_LEN {
        return line;
    }

    let Some(condition_lines) = format_wrapped_condition_lines(condition, indent + 1, context)
    else {
        return line;
    };
    let mut output = String::new();
    output.push_str(&pad);
    output.push_str(keyword);
    output.push_str(" (\n");
    for line in condition_lines {
        output.push_str(&line);
        output.push('\n');
    }
    output.push_str(&pad);
    output.push_str(") {\n");
    output
}

fn format_wrapped_condition_lines(
    condition: &AstExpression,
    indent: usize,
    context: &CPrintContext<'_>,
) -> Option<Vec<String>> {
    let AstExpression::Binary { op, ty, .. } = condition else {
        return None;
    };
    if !matches!(ty, AstType::Integer(1))
        || !matches!(op, AstBinaryOperation::And | AstBinaryOperation::Or)
    {
        return None;
    }

    let mut terms = Vec::new();
    collect_logical_terms(condition, *op, context, &mut terms);
    if terms.len() < 2 {
        return None;
    }
    let pad = "    ".repeat(indent);
    let operator = match op {
        AstBinaryOperation::And => "&&",
        AstBinaryOperation::Or => "||",
        _ => unreachable!(),
    };
    let mut lines = Vec::new();
    for (index, term) in terms.into_iter().enumerate() {
        if index == 0 {
            lines.push(format!("{pad}{term}"));
        } else {
            lines.push(format!("{pad}{operator} {term}"));
        }
    }
    Some(lines)
}

fn collect_logical_terms(
    expression: &AstExpression,
    target_op: AstBinaryOperation,
    context: &CPrintContext<'_>,
    terms: &mut Vec<String>,
) {
    match expression {
        AstExpression::Binary { op, lhs, rhs, ty }
            if *op == target_op && matches!(ty, AstType::Integer(1)) =>
        {
            collect_logical_terms(lhs, target_op, context, terms);
            collect_logical_terms(rhs, target_op, context, terms);
        }
        expression => terms.push(format_logical_condition_operand(expression, context)),
    }
}

fn format_expression(expression: &AstExpression, context: &CPrintContext<'_>) -> String {
    format_expression_inner(expression, context, true)
}

fn format_expression_without_strings(
    expression: &AstExpression,
    context: &CPrintContext<'_>,
) -> String {
    format_expression_inner(expression, context, false)
}

fn format_expression_inner(
    expression: &AstExpression,
    context: &CPrintContext<'_>,
    allow_strings: bool,
) -> String {
    if allow_strings && let Some(literal) = context.expression_string_literal(expression) {
        return literal;
    }
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
            format_subexpression_inner(lhs, context, false),
            format_binary_op(*op),
            format_subexpression_inner(rhs, context, false)
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
            if *lsb == 0 {
                return format!("({} & {:#x})", format_subexpression(value, context), mask);
            }
            format!(
                "(({} >> {}) & {:#x})",
                format_subexpression(value, context),
                lsb,
                mask
            )
        }
        AstExpression::Load {
            address_space,
            address,
            ty,
        } => {
            if let Some(intrinsic) = format_segment_load(address_space, address, ty, context) {
                return intrinsic;
            }
            if let Some(local) = format_stack_local_load(address_space, address, context) {
                return local;
            }
            format!(
                "*({}*)({})",
                format_type(ty),
                format_memory_address(address_space, address, context)
            )
        }
        AstExpression::Compare { op, lhs, rhs, .. } => format!(
            "{} {} {}",
            format_compare_operand(*op, lhs, context),
            format_compare_op(*op),
            format_compare_operand(*op, rhs, context)
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
            target,
            abi,
            arguments,
            return_types,
        } => format!(
            "{}({})",
            format_call_target(target, abi.as_ref(), return_types, arguments, context),
            arguments
                .iter()
                .enumerate()
                .map(|(index, argument)| format_call_argument(target, index, argument, context))
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
        AstExpression::Dereference { pointer, ty } => {
            format!(
                "*({}*){}",
                format_type(ty),
                format_subexpression_inner(pointer, context, false)
            )
        }
        AstExpression::Index { base, index, .. } => {
            format!(
                "{}[{}]",
                format_subexpression_inner(base, context, false),
                format_expression_without_strings(index, context)
            )
        }
        AstExpression::Member { base, name, .. } => {
            format!(
                "{}->{}",
                format_subexpression_inner(base, context, false),
                sanitize_identifier(name)
            )
        }
    }
}

fn format_call_argument(
    target: &AstTarget,
    index: usize,
    argument: &AstExpression,
    context: &CPrintContext<'_>,
) -> String {
    let preference = call_argument_string_preference(target, index);
    if preference != StringPreference::Any
        && let Some(literal) =
            context.expression_string_literal_with_preference(argument, preference)
    {
        return literal;
    }
    if preference != StringPreference::Any {
        return format_expression_without_strings(argument, context);
    }
    format_expression(argument, context)
}

fn format_condition(expression: &AstExpression, context: &CPrintContext<'_>) -> String {
    if let Some((value, bits, negated)) = sign_bit_condition(expression) {
        let op = if negated { ">=" } else { "<" };
        return format!(
            "(int{}_t){} {} 0",
            bits,
            format_subexpression(value, context),
            op
        );
    }
    if let Some(condition) = bit_test_condition(expression, context) {
        return condition;
    }
    if let Some(condition) = logical_condition(expression, context) {
        return condition;
    }
    format_expression(expression, context)
}

fn logical_condition(expression: &AstExpression, context: &CPrintContext<'_>) -> Option<String> {
    let AstExpression::Binary { op, lhs, rhs, ty } = expression else {
        return None;
    };
    if !matches!(ty, AstType::Integer(1)) {
        return None;
    }
    let op = match op {
        AstBinaryOperation::And => "&&",
        AstBinaryOperation::Or => "||",
        _ => return None,
    };
    Some(format!(
        "{} {} {}",
        format_logical_condition_operand(lhs, context),
        op,
        format_logical_condition_operand(rhs, context)
    ))
}

fn format_logical_condition_operand(
    expression: &AstExpression,
    context: &CPrintContext<'_>,
) -> String {
    if let Some(condition) = logical_condition(expression, context) {
        return format!("({condition})");
    }
    format_subexpression(expression, context)
}

fn sign_bit_condition(expression: &AstExpression) -> Option<(&AstExpression, u16, bool)> {
    match expression {
        AstExpression::Unary {
            op: AstUnaryOperation::LogicalNot,
            value,
            ..
        } => {
            let (value, bits, negated) = sign_bit_condition(value)?;
            Some((value, bits, !negated))
        }
        AstExpression::Cast { value, .. } => sign_bit_condition(value),
        AstExpression::Extract { value, lsb, ty } if integer_bits(ty) == Some(1) => {
            let bits = expression_integer_bits(value)?;
            (*lsb + 1 == bits && matches!(bits, 8 | 16 | 32 | 64 | 128)).then_some((
                value.as_ref(),
                bits,
                false,
            ))
        }
        AstExpression::Binary {
            op: AstBinaryOperation::And,
            lhs,
            rhs,
            ..
        } => {
            if is_one_ast_expression(rhs) {
                sign_bit_shift_condition(lhs)
            } else if is_one_ast_expression(lhs) {
                sign_bit_shift_condition(rhs)
            } else {
                None
            }
        }
        AstExpression::Compare { op, lhs, rhs, .. }
            if matches!(op, AstCompareOperation::Eq | AstCompareOperation::Ne) =>
        {
            let candidate = if is_zero_ast_expression(rhs) {
                lhs.as_ref()
            } else if is_zero_ast_expression(lhs) {
                rhs.as_ref()
            } else {
                return None;
            };
            let (value, bits, negated) = sign_bit_condition(candidate)?;
            let equals_zero = matches!(op, AstCompareOperation::Eq);
            Some((value, bits, negated ^ equals_zero))
        }
        _ => None,
    }
}

fn sign_bit_shift_condition(expression: &AstExpression) -> Option<(&AstExpression, u16, bool)> {
    let expression = peel_casts(expression);
    let AstExpression::Binary {
        op: AstBinaryOperation::LShr | AstBinaryOperation::AShr,
        lhs,
        rhs,
        ..
    } = expression
    else {
        return None;
    };
    let shift = expression_integer_value(rhs)?;
    let bits = u16::try_from(shift + 1).ok()?;
    matches!(bits, 8 | 16 | 32 | 64 | 128).then_some((lhs.as_ref(), bits, false))
}

fn bit_test_condition(expression: &AstExpression, context: &CPrintContext<'_>) -> Option<String> {
    let (value, bit, negated) = raw_bit_test_condition(expression)?;
    if let Some(bits) = sign_width_for_bit(bit) {
        let op = if negated { ">=" } else { "<" };
        return Some(format!(
            "(int{}_t){} {} 0",
            bits,
            format_subexpression(value, context),
            op
        ));
    }
    let mask = 1u128.checked_shl(u32::from(bit))?;
    let op = if negated { "==" } else { "!=" };
    Some(format!(
        "({} & {}) {} 0",
        format_subexpression(value, context),
        format_hex_mask(mask),
        op
    ))
}

fn raw_bit_test_condition(expression: &AstExpression) -> Option<(&AstExpression, u16, bool)> {
    match expression {
        AstExpression::Unary {
            op: AstUnaryOperation::LogicalNot,
            value,
            ..
        } => {
            let (value, bit, negated) = raw_bit_test_condition(value)?;
            Some((value, bit, !negated))
        }
        AstExpression::Cast { value, .. } => raw_bit_test_condition(value),
        AstExpression::Extract { value, lsb, ty } if integer_bits(ty) == Some(1) => {
            Some((value.as_ref(), *lsb, false))
        }
        AstExpression::Binary {
            op: AstBinaryOperation::And,
            lhs,
            rhs,
            ..
        } => {
            if is_one_ast_expression(rhs) {
                shifted_bit_condition(lhs)
            } else if is_one_ast_expression(lhs) {
                shifted_bit_condition(rhs)
            } else {
                None
            }
        }
        AstExpression::Compare { op, lhs, rhs, .. }
            if matches!(op, AstCompareOperation::Eq | AstCompareOperation::Ne) =>
        {
            let candidate = if is_zero_ast_expression(rhs) {
                lhs.as_ref()
            } else if is_zero_ast_expression(lhs) {
                rhs.as_ref()
            } else {
                return None;
            };
            let (value, bit, negated) = raw_bit_test_condition(candidate)?;
            let equals_zero = matches!(op, AstCompareOperation::Eq);
            Some((value, bit, negated ^ equals_zero))
        }
        _ => None,
    }
}

fn shifted_bit_condition(expression: &AstExpression) -> Option<(&AstExpression, u16, bool)> {
    let expression = peel_casts(expression);
    let AstExpression::Binary {
        op: AstBinaryOperation::LShr | AstBinaryOperation::AShr,
        lhs,
        rhs,
        ..
    } = expression
    else {
        return None;
    };
    let shift = expression_integer_value(rhs)?;
    Some((lhs.as_ref(), u16::try_from(shift).ok()?, false))
}

fn sign_width_for_bit(bit: u16) -> Option<u16> {
    match bit + 1 {
        bits @ (8 | 16 | 32 | 64 | 128) => Some(bits),
        _ => None,
    }
}

fn peel_casts(mut expression: &AstExpression) -> &AstExpression {
    while let AstExpression::Cast { value, .. } = expression {
        expression = value;
    }
    expression
}

fn expression_has_c_side_effects(expression: &AstExpression) -> bool {
    match expression {
        AstExpression::Call { .. } | AstExpression::Intrinsic { .. } => true,
        AstExpression::Unary { value, .. }
        | AstExpression::Extract { value, .. }
        | AstExpression::Cast { value, .. }
        | AstExpression::Dereference { pointer: value, .. } => expression_has_c_side_effects(value),
        AstExpression::Binary { lhs, rhs, .. }
        | AstExpression::Compare { lhs, rhs, .. }
        | AstExpression::FloatCompare { lhs, rhs, .. }
        | AstExpression::Index {
            base: lhs,
            index: rhs,
            ..
        } => expression_has_c_side_effects(lhs) || expression_has_c_side_effects(rhs),
        AstExpression::Member { base, .. } => expression_has_c_side_effects(base),
        AstExpression::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            expression_has_c_side_effects(condition)
                || expression_has_c_side_effects(when_true)
                || expression_has_c_side_effects(when_false)
        }
        AstExpression::Concat { parts, .. } => parts.iter().any(expression_has_c_side_effects),
        AstExpression::Load { address, .. } => expression_has_c_side_effects(address),
        AstExpression::AddressOf { .. } | AstExpression::Value(_) => false,
    }
}

fn format_hex_mask(mask: u128) -> String {
    if mask == u128::from(u64::MAX) {
        format!("{mask:#x}ULL")
    } else {
        format!("{mask:#x}")
    }
}

fn is_one_ast_expression(expression: &AstExpression) -> bool {
    matches!(
        expression,
        AstExpression::Value(AstValue::Integer { value: 1, .. })
            | AstExpression::Value(AstValue::Boolean(true))
    )
}

fn is_zero_ast_expression(expression: &AstExpression) -> bool {
    matches!(
        expression,
        AstExpression::Value(AstValue::Integer { value: 0, .. })
            | AstExpression::Value(AstValue::Boolean(false))
    )
}

fn call_argument_string_preference(target: &AstTarget, index: usize) -> StringPreference {
    let AstTarget::Direct(name) = target else {
        return StringPreference::Any;
    };
    match (display_symbol_name(name), index) {
        ("LoadLibraryExW" | "LoadLibraryW", 0) => StringPreference::WideModule,
        ("LoadLibraryExA" | "LoadLibraryA", 0) => StringPreference::Ascii,
        ("GetProcAddress", 1) => StringPreference::Ascii,
        _ => StringPreference::Any,
    }
}

fn format_subexpression(expression: &AstExpression, context: &CPrintContext<'_>) -> String {
    format_subexpression_inner(expression, context, true)
}

fn format_subexpression_inner(
    expression: &AstExpression,
    context: &CPrintContext<'_>,
    allow_strings: bool,
) -> String {
    match expression {
        AstExpression::Value(_)
        | AstExpression::Call { .. }
        | AstExpression::Intrinsic { .. }
        | AstExpression::Load { .. }
        | AstExpression::Dereference { .. }
        | AstExpression::Index { .. }
        | AstExpression::Member { .. } => {
            format_expression_inner(expression, context, allow_strings)
        }
        _ => format!(
            "({})",
            format_expression_inner(expression, context, allow_strings)
        ),
    }
}

fn format_place(place: &AstPlace, context: &CPrintContext<'_>) -> String {
    match place {
        AstPlace::Named { name, .. } => context.local_name(name),
        AstPlace::Dereference { pointer, ty } => {
            format!(
                "*({}*){}",
                format_type(ty),
                format_subexpression_inner(pointer, context, false)
            )
        }
        AstPlace::Memory {
            address_space,
            address,
            ty,
        } => {
            if let Some(local) = format_stack_local_load(address_space, address, context) {
                return local;
            }
            format!(
                "*({}*){}",
                format_type(ty),
                format_memory_address(address_space, address, context)
            )
        }
        AstPlace::Index { base, index, .. } => {
            format!(
                "{}[{}]",
                format_subexpression_inner(base, context, false),
                format_expression_without_strings(index, context)
            )
        }
    }
}

fn format_stack_local_load(
    address_space: &AstAddressSpace,
    address: &AstExpression,
    context: &CPrintContext<'_>,
) -> Option<String> {
    let (base, offset) = stack_memory_location(address_space, address)?;
    if context.suppressed_stack_local_load.borrow().as_ref() == Some(&(base.clone(), offset)) {
        return None;
    }
    context.stack_local_name(&base, offset)
}

fn place_stack_location(place: &AstPlace, context: &CPrintContext<'_>) -> Option<(String, i64)> {
    match place {
        AstPlace::Named { name, .. } => context.local_stack_location(name),
        AstPlace::Memory {
            address_space,
            address,
            ..
        } => stack_memory_location(address_space, address),
        AstPlace::Dereference { .. } | AstPlace::Index { .. } => None,
    }
}

fn format_memory_address(
    address_space: &AstAddressSpace,
    address: &AstExpression,
    context: &CPrintContext<'_>,
) -> String {
    if matches!(address_space, AstAddressSpace::Default) {
        return format_subexpression_inner(address, context, false);
    }
    if let Some(address) = format_stack_memory_address(address_space, address, context) {
        return address;
    }
    format_address_expression(address_space, address, context)
}

fn format_stack_memory_address(
    address_space: &AstAddressSpace,
    address: &AstExpression,
    context: &CPrintContext<'_>,
) -> Option<String> {
    let Some((base, offset)) = stack_memory_location(address_space, address) else {
        return matches!(address_space, AstAddressSpace::Stack)
            .then(|| format_address_expression(address_space, address, context));
    };
    let c_address = if expression_integer_value(address).is_some() {
        format_stack_base_address(&base, offset, context)
    } else {
        format_expression_without_strings(address, context)
    };
    Some(c_address)
}

fn format_stack_base_address(base: &str, offset: i64, context: &CPrintContext<'_>) -> String {
    let Some(base_name) = context.register_local_name(base) else {
        return format_integer_literal(i128::from(offset), 64);
    };
    if offset == 0 {
        base_name.to_string()
    } else if offset > 0 {
        format!(
            "{base_name} + {}",
            format_integer_literal(i128::from(offset), 64)
        )
    } else {
        format!(
            "{base_name} - {}",
            format_integer_literal(i128::from(-offset), 64)
        )
    }
}

fn stack_memory_location(
    address_space: &AstAddressSpace,
    address: &AstExpression,
) -> Option<(String, i64)> {
    let offset = i64::try_from(expression_integer_value(address)?).ok()?;
    match address_space {
        AstAddressSpace::Stack => Some(("rsp".to_string(), offset)),
        AstAddressSpace::Local { name } | AstAddressSpace::Spill { name } => Some((
            "rbp".to_string(),
            i64::try_from(-parse_address_space_offset(name)?).ok()? + offset,
        )),
        AstAddressSpace::Argument { name } | AstAddressSpace::Incoming { name } => Some((
            "rsp".to_string(),
            i64::try_from(parse_address_space_offset(name)?).ok()? + offset,
        )),
        AstAddressSpace::SavedFrame { .. } | AstAddressSpace::ReturnAddress { .. } => {
            Some(("rsp".to_string(), offset))
        }
        _ => None,
    }
}

fn format_address_expression(
    address_space: &AstAddressSpace,
    address: &AstExpression,
    context: &CPrintContext<'_>,
) -> String {
    let base = address_space_base_offset(address_space);
    let offset = expression_integer_value(address);
    match (base, offset) {
        (Some(base), Some(offset)) => format_integer_literal(base + offset, 64),
        (Some(0), None) | (None, None) => format_subexpression_inner(address, context, false),
        (Some(base), None) => format!(
            "({} + {})",
            format_integer_literal(base, 64),
            format_expression_without_strings(address, context)
        ),
        (None, Some(offset)) => format_integer_literal(offset, 64),
    }
}

fn format_stack_address_comment(base: &str, offset: i128) -> String {
    if offset == 0 {
        return format!("[{base}]");
    }
    if offset < 0 {
        format!("[{base}-0x{:x}]", offset.unsigned_abs())
    } else {
        format!("[{base}+0x{offset:x}]")
    }
}

fn format_segment_load(
    address_space: &AstAddressSpace,
    address: &AstExpression,
    ty: &AstType,
    context: &CPrintContext<'_>,
) -> Option<String> {
    let AstAddressSpace::Named { name } = address_space else {
        return None;
    };
    let intrinsic = match (name.as_str(), integer_bits(ty).unwrap_or(type_bits(ty))) {
        ("gs", 8) => "__readgsbyte",
        ("gs", 16) => "__readgsword",
        ("gs", 32) => "__readgsdword",
        ("gs", 64) => "__readgsqword",
        ("fs", 8) => "__readfsbyte",
        ("fs", 16) => "__readfsword",
        ("fs", 32) => "__readfsdword",
        ("fs", 64) => "__readfsqword",
        _ => return None,
    };
    Some(format!(
        "{}({})",
        intrinsic,
        format_address_space_offset(address_space, address, context)
    ))
}

fn format_segment_store(
    target: &AstPlace,
    value: &AstExpression,
    context: &CPrintContext<'_>,
) -> Option<String> {
    let AstPlace::Memory {
        address_space,
        address,
        ty,
    } = target
    else {
        return None;
    };
    let AstAddressSpace::Named { name } = address_space else {
        return None;
    };
    let intrinsic = match (name.as_str(), integer_bits(ty).unwrap_or(type_bits(ty))) {
        ("gs", 8) => "__writegsbyte",
        ("gs", 16) => "__writegsword",
        ("gs", 32) => "__writegsdword",
        ("gs", 64) => "__writegsqword",
        ("fs", 8) => "__writefsbyte",
        ("fs", 16) => "__writefsword",
        ("fs", 32) => "__writefsdword",
        ("fs", 64) => "__writefsqword",
        _ => return None,
    };
    Some(format!(
        "{}({}, {})",
        intrinsic,
        format_address_space_offset(address_space, address, context),
        format_expression(value, context)
    ))
}

fn format_address_space_offset(
    address_space: &AstAddressSpace,
    address: &AstExpression,
    context: &CPrintContext<'_>,
) -> String {
    let base = address_space_base_offset(address_space);
    let offset = expression_integer_value(address);
    match (base, offset) {
        (Some(base), Some(offset)) => format_c_offset(base + offset),
        (Some(base), None) if base == 0 => format_expression_without_strings(address, context),
        (Some(base), None) => {
            format!(
                "{} + {}",
                format_c_offset(base),
                format_expression_without_strings(address, context)
            )
        }
        (None, Some(offset)) => format_c_offset(offset),
        (None, None) => format_expression_without_strings(address, context),
    }
}

fn address_space_base_offset(address_space: &AstAddressSpace) -> Option<i128> {
    match address_space {
        AstAddressSpace::Local { name }
        | AstAddressSpace::Argument { name }
        | AstAddressSpace::Spill { name }
        | AstAddressSpace::Incoming { name }
        | AstAddressSpace::SavedFrame { name }
        | AstAddressSpace::ReturnAddress { name } => parse_address_space_offset(name),
        AstAddressSpace::Default
        | AstAddressSpace::Stack
        | AstAddressSpace::Heap
        | AstAddressSpace::Global
        | AstAddressSpace::HeapObject { .. }
        | AstAddressSpace::GlobalObject { .. }
        | AstAddressSpace::Io
        | AstAddressSpace::Named { .. } => None,
    }
}

fn parse_address_space_offset(name: &str) -> Option<i128> {
    let suffix = name.strip_prefix('m').unwrap_or(name);
    suffix.parse::<i128>().ok()
}

fn expression_integer_value(expression: &AstExpression) -> Option<i128> {
    match expression {
        AstExpression::Value(AstValue::Integer { value, .. }) => Some(*value),
        _ => None,
    }
}

fn format_c_offset(value: i128) -> String {
    if value < 0 {
        format!("-0x{:x}", value.unsigned_abs())
    } else {
        format!("0x{value:x}")
    }
}

fn format_target(target: &AstTarget, context: &CPrintContext<'_>) -> String {
    match target {
        AstTarget::Direct(name) => sanitize_identifier(name),
        AstTarget::Indirect(expression) => {
            format!("*{}", format_subexpression(expression, context))
        }
    }
}

fn format_call_target(
    target: &AstTarget,
    abi: Option<&LirAbi>,
    return_types: &[AstType],
    arguments: &[AstExpression],
    context: &CPrintContext<'_>,
) -> String {
    match target {
        AstTarget::Direct(name) => sanitize_identifier(display_symbol_name(name)),
        AstTarget::Indirect(expression) => {
            if let Some(convention) = abi.and_then(format_abi_function_pointer_convention) {
                format!(
                    "(({} ({convention}*)({})){})",
                    format_return_type(return_types),
                    arguments
                        .iter()
                        .map(|argument| format_type(&expression_type(argument)))
                        .collect::<Vec<_>>()
                        .join(", "),
                    format_expression(expression, context)
                )
            } else {
                format!("(*{})", format_expression(expression, context))
            }
        }
    }
}

fn format_compare_operand(
    op: AstCompareOperation,
    expression: &AstExpression,
    context: &CPrintContext<'_>,
) -> String {
    let operand = format_subexpression(expression, context);
    if !matches!(
        op,
        AstCompareOperation::Slt
            | AstCompareOperation::Sle
            | AstCompareOperation::Sgt
            | AstCompareOperation::Sge
    ) {
        return operand;
    }
    if let AstExpression::Value(AstValue::Integer { value, .. }) = expression {
        return format_signed_integer_literal(*value);
    }
    let Some(bits) = expression_integer_bits(expression) else {
        return operand;
    };
    match bits {
        8 | 16 | 32 | 64 | 128 => format!("(int{bits}_t){operand}"),
        _ => operand,
    }
}

fn format_signed_integer_literal(value: i128) -> String {
    if value == 0 {
        return "0".to_string();
    }
    if (1..=9).contains(&value) {
        return value.to_string();
    }
    if value < 0 {
        return format!("-0x{:x}", value.unsigned_abs());
    }
    format!("0x{value:x}")
}

fn expression_integer_bits(expression: &AstExpression) -> Option<u16> {
    match expression {
        AstExpression::Value(value) => integer_bits(&value.ty()),
        AstExpression::Unary { ty, .. }
        | AstExpression::Binary { ty, .. }
        | AstExpression::Select { ty, .. }
        | AstExpression::Concat { ty, .. }
        | AstExpression::Extract { ty, .. }
        | AstExpression::Load { ty, .. }
        | AstExpression::Compare { ty, .. }
        | AstExpression::FloatCompare { ty, .. }
        | AstExpression::Cast { ty, .. }
        | AstExpression::AddressOf { ty, .. }
        | AstExpression::Dereference { ty, .. }
        | AstExpression::Index { ty, .. }
        | AstExpression::Member { ty, .. } => integer_bits(ty),
        AstExpression::Call { return_types, .. }
        | AstExpression::Intrinsic { return_types, .. } => {
            return_types.first().and_then(integer_bits)
        }
    }
}

fn expression_type(expression: &AstExpression) -> AstType {
    match expression {
        AstExpression::Value(value) => value.ty(),
        AstExpression::Unary { ty, .. }
        | AstExpression::Binary { ty, .. }
        | AstExpression::Select { ty, .. }
        | AstExpression::Concat { ty, .. }
        | AstExpression::Extract { ty, .. }
        | AstExpression::Load { ty, .. }
        | AstExpression::Compare { ty, .. }
        | AstExpression::FloatCompare { ty, .. }
        | AstExpression::Cast { ty, .. }
        | AstExpression::AddressOf { ty, .. }
        | AstExpression::Dereference { ty, .. }
        | AstExpression::Index { ty, .. }
        | AstExpression::Member { ty, .. } => ty.clone(),
        AstExpression::Call { return_types, .. }
        | AstExpression::Intrinsic { return_types, .. } => {
            return_types.first().cloned().unwrap_or_else(AstType::void)
        }
    }
}

fn display_symbol_name(name: &str) -> &str {
    name.rsplit_once('!')
        .map(|(_, symbol)| symbol)
        .unwrap_or(name)
}

fn string_literal_matches_preference(literal: &str, preference: StringPreference) -> bool {
    match preference {
        StringPreference::Any => true,
        StringPreference::Ascii => !literal.starts_with("L\""),
        StringPreference::WideModule => {
            literal.starts_with("L\"") && string_literal_body(literal).is_some_and(is_module_name)
        }
    }
}

fn string_literal_body(literal: &str) -> Option<&str> {
    literal
        .strip_prefix("L\"")
        .or_else(|| literal.strip_prefix('"'))
        .and_then(|body| body.strip_suffix('"'))
}

fn is_module_name(body: &str) -> bool {
    body.rsplit(['\\', '/'])
        .next()
        .is_some_and(|name| name.to_ascii_lowercase().ends_with(".dll"))
}

fn parse_function_address(name: &str) -> Option<u64> {
    let suffix = name.strip_prefix("function_")?;
    let hex = suffix
        .chars()
        .take_while(|ch| ch.is_ascii_hexdigit())
        .collect::<String>();
    if hex.is_empty() {
        return None;
    }
    u64::from_str_radix(&hex, 16).ok()
}

fn format_value(value: &AstValue, context: &CPrintContext<'_>) -> String {
    match value {
        AstValue::Named { name, .. } => context.local_name(name),
        AstValue::Integer { value, bits } => format_integer_literal(*value, *bits),
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

fn decode_ascii_string_literal(bytes: &[u8]) -> Option<String> {
    let end = bytes.iter().position(|byte| *byte == 0)?;
    let string = &bytes[..end];
    if string.len() < MIN_STRING_CHARS || !string.iter().all(|byte| is_ascii_string_byte(*byte)) {
        return None;
    }
    Some(format!("\"{}\"", escape_ascii_string(string)))
}

fn decode_wide_string_literal(bytes: &[u8]) -> Option<String> {
    let mut units = Vec::new();
    for chunk in bytes.chunks_exact(2) {
        let unit = u16::from_le_bytes([chunk[0], chunk[1]]);
        if unit == 0 {
            break;
        }
        units.push(unit);
    }
    if units.len() < MIN_STRING_CHARS {
        return None;
    }
    let string = String::from_utf16(&units).ok()?;
    if !string.chars().all(is_c_string_char) {
        return None;
    }
    let char_count = string.chars().count();
    let ascii_count = string
        .chars()
        .filter(|ch| ch.is_ascii_graphic() || *ch == ' ')
        .count();
    if ascii_count * 4 < char_count * 3 {
        return None;
    }
    Some(format!("L\"{}\"", escape_wide_string(&string)))
}

fn is_likely_utf16_unit(bytes: &[u8]) -> bool {
    if bytes.len() != 2 {
        return false;
    }
    let unit = u16::from_le_bytes([bytes[0], bytes[1]]);
    if unit == 0 {
        return false;
    }
    char::from_u32(unit as u32).is_some_and(is_c_string_char)
}

fn is_utf16_path_separator(bytes: &[u8]) -> bool {
    bytes.len() == 2 && matches!(u16::from_le_bytes([bytes[0], bytes[1]]), 0x5c | 0x2f)
}

fn is_ascii_string_byte(byte: u8) -> bool {
    matches!(byte, b'\t' | b'\n' | b'\r' | b' '..=b'~')
}

fn is_c_string_char(ch: char) -> bool {
    matches!(ch, '\t' | '\n' | '\r') || (!ch.is_control() && ch != '\0')
}

fn escape_ascii_string(bytes: &[u8]) -> String {
    let mut output = String::new();
    for byte in bytes {
        match *byte {
            b'\\' => output.push_str("\\\\"),
            b'"' => output.push_str("\\\""),
            b'\n' => output.push_str("\\n"),
            b'\r' => output.push_str("\\r"),
            b'\t' => output.push_str("\\t"),
            b' '..=b'~' => output.push(*byte as char),
            _ => output.push_str(&format!("\\x{byte:02x}")),
        }
    }
    output
}

fn escape_wide_string(string: &str) -> String {
    let mut output = String::new();
    for ch in string.chars() {
        match ch {
            '\\' => output.push_str("\\\\"),
            '"' => output.push_str("\\\""),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            ch if ch.is_ascii_graphic() || ch == ' ' => output.push(ch),
            ch if (ch as u32) <= 0xffff => output.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => output.push_str(&format!("\\U{:08x}", ch as u32)),
        }
    }
    output
}

fn collect_assigned_named_places(block: &AstBlock, locals: &mut BTreeMap<String, AstType>) {
    for statement in &block.statements {
        collect_assigned_named_places_in_statement(statement, locals);
    }
}

fn collect_referenced_named_values(block: &AstBlock, locals: &mut BTreeMap<String, AstType>) {
    for statement in &block.statements {
        collect_referenced_named_values_in_statement(statement, locals);
    }
}

fn collect_stack_memory_slots(block: &AstBlock, slots: &mut BTreeMap<(String, i64), AstType>) {
    for statement in &block.statements {
        collect_stack_memory_slots_in_statement(statement, slots);
    }
}

fn collect_stack_memory_slots_in_statement(
    statement: &AstStatement,
    slots: &mut BTreeMap<(String, i64), AstType>,
) {
    match statement {
        AstStatement::Assign { target, value } => {
            collect_stack_memory_slots_in_place(target, slots);
            collect_stack_memory_slots_in_expression(value, slots);
        }
        AstStatement::Expr(value) => collect_stack_memory_slots_in_expression(value, slots),
        AstStatement::If {
            condition,
            then_body,
            else_body,
        } => {
            collect_stack_memory_slots_in_expression(condition, slots);
            collect_stack_memory_slots(then_body, slots);
            if let Some(else_body) = else_body {
                collect_stack_memory_slots(else_body, slots);
            }
        }
        AstStatement::While { condition, body } => {
            collect_stack_memory_slots_in_expression(condition, slots);
            collect_stack_memory_slots(body, slots);
        }
        AstStatement::Loop { body } => collect_stack_memory_slots(body, slots),
        AstStatement::Switch {
            value,
            cases,
            default,
        } => {
            collect_stack_memory_slots_in_expression(value, slots);
            for case in cases {
                collect_stack_memory_slots(&case.body, slots);
            }
            if let Some(default) = default {
                collect_stack_memory_slots(default, slots);
            }
        }
        AstStatement::Return { values } => {
            for value in values {
                collect_stack_memory_slots_in_expression(value, slots);
            }
        }
        AstStatement::Goto(AstTarget::Indirect(value)) => {
            collect_stack_memory_slots_in_expression(value, slots);
        }
        AstStatement::Break
        | AstStatement::Continue
        | AstStatement::Comment(_)
        | AstStatement::Label(_)
        | AstStatement::Goto(AstTarget::Direct(_))
        | AstStatement::Trap
        | AstStatement::Unreachable => {}
    }
}

fn collect_stack_memory_slots_in_expression(
    expression: &AstExpression,
    slots: &mut BTreeMap<(String, i64), AstType>,
) {
    match expression {
        AstExpression::Load {
            address_space,
            address,
            ty,
        } => {
            record_stack_memory_slot(address_space, address, ty, slots);
            collect_stack_memory_slots_in_expression(address, slots);
        }
        AstExpression::Unary { value, .. }
        | AstExpression::Extract { value, .. }
        | AstExpression::Cast { value, .. }
        | AstExpression::Dereference { pointer: value, .. } => {
            collect_stack_memory_slots_in_expression(value, slots);
        }
        AstExpression::Binary { lhs, rhs, .. }
        | AstExpression::Compare { lhs, rhs, .. }
        | AstExpression::FloatCompare { lhs, rhs, .. } => {
            collect_stack_memory_slots_in_expression(lhs, slots);
            collect_stack_memory_slots_in_expression(rhs, slots);
        }
        AstExpression::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            collect_stack_memory_slots_in_expression(condition, slots);
            collect_stack_memory_slots_in_expression(when_true, slots);
            collect_stack_memory_slots_in_expression(when_false, slots);
        }
        AstExpression::Concat { parts, .. } => {
            for part in parts {
                collect_stack_memory_slots_in_expression(part, slots);
            }
        }
        AstExpression::Call {
            target, arguments, ..
        } => {
            collect_stack_memory_slots_in_target(target, slots);
            for argument in arguments {
                collect_stack_memory_slots_in_expression(argument, slots);
            }
        }
        AstExpression::Intrinsic { arguments, .. } => {
            for argument in arguments {
                collect_stack_memory_slots_in_expression(argument, slots);
            }
        }
        AstExpression::AddressOf { place, .. } => collect_stack_memory_slots_in_place(place, slots),
        AstExpression::Member { base, .. } => collect_stack_memory_slots_in_expression(base, slots),
        AstExpression::Index { base, index, .. } => {
            collect_stack_memory_slots_in_expression(base, slots);
            collect_stack_memory_slots_in_expression(index, slots);
        }
        AstExpression::Value(_) => {}
    }
}

fn collect_stack_memory_slots_in_place(
    place: &AstPlace,
    slots: &mut BTreeMap<(String, i64), AstType>,
) {
    match place {
        AstPlace::Memory {
            address_space,
            address,
            ty,
        } => {
            record_stack_memory_slot(address_space, address, ty, slots);
            collect_stack_memory_slots_in_expression(address, slots);
        }
        AstPlace::Dereference { pointer, .. } => {
            collect_stack_memory_slots_in_expression(pointer, slots)
        }
        AstPlace::Index { base, index, .. } => {
            collect_stack_memory_slots_in_expression(base, slots);
            collect_stack_memory_slots_in_expression(index, slots);
        }
        AstPlace::Named { .. } => {}
    }
}

fn collect_stack_memory_slots_in_target(
    target: &AstTarget,
    slots: &mut BTreeMap<(String, i64), AstType>,
) {
    if let AstTarget::Indirect(expression) = target {
        collect_stack_memory_slots_in_expression(expression, slots);
    }
}

fn record_stack_memory_slot(
    address_space: &AstAddressSpace,
    address: &AstExpression,
    ty: &AstType,
    slots: &mut BTreeMap<(String, i64), AstType>,
) {
    let Some(location) = stack_memory_location(address_space, address) else {
        return;
    };
    slots
        .entry(location)
        .and_modify(|existing| {
            if type_bits(ty) > type_bits(existing) {
                *existing = ty.clone();
            }
        })
        .or_insert_with(|| ty.clone());
}

fn collect_referenced_named_values_in_statement(
    statement: &AstStatement,
    locals: &mut BTreeMap<String, AstType>,
) {
    match statement {
        AstStatement::Assign { target, value } => {
            collect_referenced_named_values_in_place(target, locals);
            collect_referenced_named_values_in_expression(value, locals);
        }
        AstStatement::Expr(value) => collect_referenced_named_values_in_expression(value, locals),
        AstStatement::If {
            condition,
            then_body,
            else_body,
        } => {
            collect_referenced_named_values_in_expression(condition, locals);
            collect_referenced_named_values(then_body, locals);
            if let Some(else_body) = else_body {
                collect_referenced_named_values(else_body, locals);
            }
        }
        AstStatement::While { condition, body } => {
            collect_referenced_named_values_in_expression(condition, locals);
            collect_referenced_named_values(body, locals);
        }
        AstStatement::Loop { body } => collect_referenced_named_values(body, locals),
        AstStatement::Switch {
            value,
            cases,
            default,
        } => {
            collect_referenced_named_values_in_expression(value, locals);
            for case in cases {
                collect_referenced_named_values(&case.body, locals);
            }
            if let Some(default) = default {
                collect_referenced_named_values(default, locals);
            }
        }
        AstStatement::Return { values } => {
            for value in values {
                collect_referenced_named_values_in_expression(value, locals);
            }
        }
        AstStatement::Goto(AstTarget::Indirect(value)) => {
            collect_referenced_named_values_in_expression(value, locals);
        }
        AstStatement::Break
        | AstStatement::Continue
        | AstStatement::Comment(_)
        | AstStatement::Label(_)
        | AstStatement::Goto(AstTarget::Direct(_))
        | AstStatement::Trap
        | AstStatement::Unreachable => {}
    }
}

fn collect_referenced_named_values_in_expression(
    expression: &AstExpression,
    locals: &mut BTreeMap<String, AstType>,
) {
    match expression {
        AstExpression::Value(AstValue::Named { name, ty }) => {
            locals.entry(name.clone()).or_insert_with(|| ty.clone());
        }
        AstExpression::Unary { value, .. }
        | AstExpression::Extract { value, .. }
        | AstExpression::Cast { value, .. } => {
            collect_referenced_named_values_in_expression(value, locals);
        }
        AstExpression::Binary { lhs, rhs, .. }
        | AstExpression::Compare { lhs, rhs, .. }
        | AstExpression::FloatCompare { lhs, rhs, .. } => {
            collect_referenced_named_values_in_expression(lhs, locals);
            collect_referenced_named_values_in_expression(rhs, locals);
        }
        AstExpression::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            collect_referenced_named_values_in_expression(condition, locals);
            collect_referenced_named_values_in_expression(when_true, locals);
            collect_referenced_named_values_in_expression(when_false, locals);
        }
        AstExpression::Concat { parts, .. } => {
            for part in parts {
                collect_referenced_named_values_in_expression(part, locals);
            }
        }
        AstExpression::Load { address, .. } => {
            collect_referenced_named_values_in_expression(address, locals);
        }
        AstExpression::Call {
            target, arguments, ..
        } => {
            collect_referenced_named_values_in_target(target, locals);
            for argument in arguments {
                collect_referenced_named_values_in_expression(argument, locals);
            }
        }
        AstExpression::Intrinsic { arguments, .. } => {
            for argument in arguments {
                collect_referenced_named_values_in_expression(argument, locals);
            }
        }
        AstExpression::AddressOf { place, .. } => {
            collect_referenced_named_values_in_place(place, locals);
        }
        AstExpression::Dereference { pointer, .. } => {
            collect_referenced_named_values_in_expression(pointer, locals);
        }
        AstExpression::Member { base, .. } => {
            collect_referenced_named_values_in_expression(base, locals);
        }
        AstExpression::Index { base, index, .. } => {
            collect_referenced_named_values_in_expression(base, locals);
            collect_referenced_named_values_in_expression(index, locals);
        }
        AstExpression::Value(_) => {}
    }
}

fn collect_referenced_named_values_in_place(
    place: &AstPlace,
    locals: &mut BTreeMap<String, AstType>,
) {
    match place {
        AstPlace::Named { .. } => {}
        AstPlace::Dereference { pointer, .. }
        | AstPlace::Memory {
            address: pointer, ..
        } => {
            collect_referenced_named_values_in_expression(pointer, locals);
        }
        AstPlace::Index { base, index, .. } => {
            collect_referenced_named_values_in_expression(base, locals);
            collect_referenced_named_values_in_expression(index, locals);
        }
    }
}

fn collect_referenced_named_values_in_target(
    target: &AstTarget,
    locals: &mut BTreeMap<String, AstType>,
) {
    if let AstTarget::Indirect(expression) = target {
        collect_referenced_named_values_in_expression(expression, locals);
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
        | AstStatement::Comment(_)
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
        AstType::Void
        | AstType::TypeDefinition { .. }
        | AstType::Structure { .. }
        | AstType::Union { .. } => "0".to_string(),
    }
}

fn format_return_type(returns: &[AstType]) -> String {
    match returns {
        [] => "void".to_string(),
        [ty] => format_type(ty),
        _ => "/* multi-return */ void".to_string(),
    }
}

fn format_abi_calling_convention(abi: Option<&LirAbi>) -> String {
    abi.and_then(format_abi_declaration_convention)
        .map(|convention| format!(" {convention}"))
        .unwrap_or_default()
}

fn format_abi_declaration_convention(abi: &LirAbi) -> Option<&'static str> {
    match abi.name.as_str() {
        "windows64" => Some("__fastcall"),
        "cdecl" => Some("__cdecl"),
        "stdcall" => Some("__stdcall"),
        "fastcall" => Some("__fastcall"),
        _ => None,
    }
}

fn format_abi_function_pointer_convention(abi: &LirAbi) -> Option<&'static str> {
    match abi.name.as_str() {
        "windows64" => Some("__fastcall "),
        "cdecl" => Some("__cdecl "),
        "stdcall" => Some("__stdcall "),
        "fastcall" => Some("__fastcall "),
        _ => None,
    }
}

fn format_type(ty: &AstType) -> String {
    match ty {
        AstType::Void => "void".to_string(),
        AstType::Integer(bits) => format_integer_type(*bits),
        AstType::Float(32) => "float".to_string(),
        AstType::Float(64) => "double".to_string(),
        AstType::Float(bits) => format!("float{bits}_t"),
        AstType::Pointer { pointee } => format!("{}*", format_type(pointee)),
        AstType::Function { .. } => "void*".to_string(),
        AstType::Memory => "uint8_t*".to_string(),
        AstType::TypeDefinition { name }
        | AstType::Structure { name, .. }
        | AstType::Union { name, .. } => sanitize_identifier(name),
    }
}

fn format_integer_type(bits: u16) -> String {
    match bits {
        0..=8 => "uint8_t".to_string(),
        9..=16 => "uint16_t".to_string(),
        17..=32 => "uint32_t".to_string(),
        33..=64 => "uint64_t".to_string(),
        65..=128 => "uint128_t".to_string(),
        _ => format!("uint{bits}_t"),
    }
}

fn type_bits(ty: &AstType) -> u16 {
    match ty {
        AstType::Integer(bits) | AstType::Float(bits) => *bits,
        AstType::Pointer { .. } | AstType::Function { .. } | AstType::Memory => 64,
        AstType::Void
        | AstType::TypeDefinition { .. }
        | AstType::Structure { .. }
        | AstType::Union { .. } => 0,
    }
}

fn format_stack_offset(offset: i64) -> String {
    if offset < 0 {
        format!("-{:x}h", offset.unsigned_abs())
    } else {
        format!("+{offset:x}h")
    }
}

fn format_storage(storage: &IrStorage, ty: &AstType) -> Option<String> {
    match storage {
        IrStorage::Register { name, .. } => Some(format_register_storage(name, type_bits(ty))),
        IrStorage::Stack { base, offset, .. } => {
            if *offset == 0 {
                Some(format!("[{base}]"))
            } else {
                Some(format!("[{}{}]", base, format_stack_offset(*offset)))
            }
        }
        IrStorage::Memory { .. } | IrStorage::Expression { .. } | IrStorage::CallReturn { .. } => {
            None
        }
    }
}

fn format_register_storage(name: &str, bits: u16) -> String {
    match (name, bits) {
        ("rax", 32) => "eax".to_string(),
        ("rbx", 32) => "ebx".to_string(),
        ("rcx", 32) => "ecx".to_string(),
        ("rdx", 32) => "edx".to_string(),
        ("rsi", 32) => "esi".to_string(),
        ("rdi", 32) => "edi".to_string(),
        ("rbp", 32) => "ebp".to_string(),
        ("rsp", 32) => "esp".to_string(),
        ("rax", 16) => "ax".to_string(),
        ("rbx", 16) => "bx".to_string(),
        ("rcx", 16) => "cx".to_string(),
        ("rdx", 16) => "dx".to_string(),
        ("rsi", 16) => "si".to_string(),
        ("rdi", 16) => "di".to_string(),
        ("rbp", 16) => "bp".to_string(),
        ("rsp", 16) => "sp".to_string(),
        (name, 32) if name.starts_with('r') && name[1..].chars().all(|ch| ch.is_ascii_digit()) => {
            format!("{name}d")
        }
        (name, 16) if name.starts_with('r') && name[1..].chars().all(|ch| ch.is_ascii_digit()) => {
            format!("{name}w")
        }
        _ => name.to_string(),
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

fn format_integer_literal(value: i128, bits: u16) -> String {
    if value == 0 {
        return "0".to_string();
    }
    if value == -1 || (bits < 128 && value == ((1i128 << bits) - 1)) {
        return format!("-1{}", integer_suffix(bits));
    }
    if (1..=9).contains(&value) {
        return value.to_string();
    }
    let suffix = integer_suffix(bits);
    if value < 0 {
        return format!("-0x{:x}{suffix}", value.unsigned_abs());
    }
    format!("0x{value:x}{suffix}")
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

fn format_comment_text(comment: &str) -> String {
    comment
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
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
