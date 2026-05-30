use crate::formats::Image;
use crate::ir::ast::{
    AstBinaryOperation, AstBlock, AstCompareOperation, AstExpression, AstFloatCompareOperation,
    AstFunction, AstLocal, AstModule, AstPlace, AstStatement, AstTarget, AstType,
    AstUnaryOperation, AstValue,
};
use crate::ir::storage::IrStorage;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

const MAX_STRING_BYTES: usize = 512;
const MIN_STRING_CHARS: usize = 4;

pub fn format_c_module(module: &AstModule) -> String {
    module
        .functions
        .iter()
        .map(format_c_function)
        .collect::<Vec<_>>()
        .join("\n\n")
}

pub fn format_c_function(function: &AstFunction) -> String {
    format_c_function_inner(function, None)
}

pub fn format_c_function_with_image(function: &AstFunction, image: &Image) -> String {
    format_c_function_inner(function, Some(image))
}

fn format_c_function_inner(function: &AstFunction, image: Option<&Image>) -> String {
    let mut output = String::new();
    let context = CPrintContext::new(function, image);
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
        if let Some(storage) = &local.storage
            && let Some(comment) = format_storage(storage, &local.ty)
        {
            output.push_str(" // ");
            output.push_str(&comment);
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

struct CPrintContext<'a> {
    local_names: BTreeMap<String, String>,
    rip_locals: BTreeSet<String>,
    entry_address: Option<u64>,
    image: Option<&'a Image>,
    string_cache: RefCell<BTreeMap<u64, Option<String>>>,
}

impl<'a> CPrintContext<'a> {
    fn new(function: &AstFunction, image: Option<&'a Image>) -> Self {
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
        let entry_address = function.name.as_deref().and_then(parse_function_address);
        Self {
            local_names,
            rip_locals,
            entry_address,
            image,
            string_cache: RefCell::new(BTreeMap::new()),
        }
    }

    fn local_name(&self, name: &str) -> String {
        self.local_names
            .get(name)
            .cloned()
            .unwrap_or_else(|| sanitize_identifier(name))
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
        if let AstExpression::Value(AstValue::Integer { value, bits }) = expression
            && *bits >= 32
            && let Ok(address) = u64::try_from(*value)
        {
            return self.normalized_string_literal(address);
        }
        let address = self.resolve_expression_address(expression)?;
        self.normalized_string_literal(address)
            .or_else(|| self.scan_forward_string_literal(address, 0x80))
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

    fn scan_forward_string_literal(&self, address: u64, max_scan: u64) -> Option<String> {
        (1..=max_scan)
            .filter_map(|offset| address.checked_add(offset))
            .find_map(|candidate| self.string_literal(candidate))
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
                format_subexpression_inner(address, context, false)
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
        | AstExpression::Deref { .. }
        | AstExpression::Index { .. } => {
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
        AstPlace::Deref { pointer, ty } => {
            format!(
                "*({}*){}",
                format_type(ty),
                format_subexpression_inner(pointer, context, false)
            )
        }
        AstPlace::Memory { address, ty, .. } => {
            format!(
                "*({}*){}",
                format_type(ty),
                format_subexpression_inner(address, context, false)
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

fn format_target(target: &AstTarget, context: &CPrintContext<'_>) -> String {
    match target {
        AstTarget::Direct(name) => sanitize_identifier(name),
        AstTarget::Indirect(expression) => {
            format!("*{}", format_subexpression(expression, context))
        }
    }
}

fn format_call_target(target: &AstTarget, context: &CPrintContext<'_>) -> String {
    match target {
        AstTarget::Direct(name) => sanitize_identifier(display_symbol_name(name)),
        AstTarget::Indirect(expression) => format!("(*{})", format_expression(expression, context)),
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
    let Some(bits) = expression_integer_bits(expression) else {
        return operand;
    };
    match bits {
        8 | 16 | 32 | 64 | 128 => format!("(int{bits}_t){operand}"),
        _ => operand,
    }
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
        | AstExpression::Deref { ty, .. }
        | AstExpression::Index { ty, .. } => integer_bits(ty),
        AstExpression::Call { return_types, .. }
        | AstExpression::Intrinsic { return_types, .. } => {
            return_types.first().and_then(integer_bits)
        }
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
        AstValue::Integer { value, bits } => {
            if *value == 0 {
                return "0".to_string();
            }
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

fn type_bits(ty: &AstType) -> u16 {
    match ty {
        AstType::Integer(bits) | AstType::Float(bits) => *bits,
        AstType::Pointer { .. } | AstType::Function { .. } | AstType::Memory => 64,
        AstType::Void | AstType::Custom { .. } => 0,
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
