use super::block::AstBlock;
use super::c::{format_c_function, format_c_module};
use super::optimizers::{optimize_ast_function, optimize_ast_module};
use super::statement::{AstLocal, AstParameter};
use crate::ir::hir::{
    HirAddressSpace, HirBinaryOperation, HirBlock, HirExpression, HirFunction, HirModule, HirPlace,
    HirStatement, HirTarget, HirValue,
};
use crate::ir::lir::LirAbi;
use crate::ir::storage::IrStorage;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct AstFunction {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abi: Option<LirAbi>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parameters: Vec<AstParameter>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub returns: Vec<super::kind::AstType>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub locals: Vec<AstLocal>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocks: Vec<AstBlock>,
}

impl AstFunction {
    pub fn from_hir(hir: &HirFunction) -> Self {
        let mut hir = hir.clone();
        optimize_hir_for_ast(&mut hir);
        let mut locals = hir
            .locals
            .iter()
            .map(AstLocal::from_hir)
            .collect::<Vec<_>>();
        let inferred_storage = infer_local_storage_with_seed(&hir.blocks, &locals);
        for local in &mut locals {
            if local.storage.is_none()
                && let Some(storage) = inferred_storage.get(&local.name)
            {
                local.storage = Some(storage.clone());
            }
        }
        let mut function = Self {
            name: hir.name.clone(),
            abi: hir.abi.clone(),
            parameters: hir.parameters.iter().map(AstParameter::from_hir).collect(),
            returns: hir.returns.clone(),
            locals,
            blocks: hir.blocks.iter().map(AstBlock::from_hir).collect(),
        };
        optimize_ast_function(&mut function);
        function
    }

    pub fn optimize(&mut self) {
        optimize_ast_function(self);
    }

    pub fn c(&self) -> String {
        format_c_function(self)
    }

    pub fn print_c(&self) {
        println!("{}", self.c());
    }

    pub fn text(&self) -> String {
        self.c()
    }

    pub fn print(&self) {
        self.print_c();
    }
}

fn optimize_hir_for_ast(hir: &mut HirFunction) {
    hir.optimize_inline_temps();
    hir.optimize_algebraic();
    hir.optimize_condition_idioms();
    hir.optimize_boolean();
    hir.optimize_load_hoisting();
    hir.optimize_call_arguments();
    hir.optimize_memory_forms();
    hir.optimize_pointer_reads();
    hir.optimize_cfg();
    hir.optimize_undefs();
    hir.optimize_inline_temps();
    hir.optimize_undefs();
    hir.optimize_algebraic();
    hir.optimize_condition_idioms();
    hir.optimize_boolean();
    hir.optimize_locals();
}

#[cfg(test)]
fn infer_local_storage(blocks: &[HirBlock]) -> BTreeMap<String, IrStorage> {
    infer_local_storage_with_seed(blocks, &[])
}

fn infer_local_storage_with_seed(
    blocks: &[HirBlock],
    locals: &[AstLocal],
) -> BTreeMap<String, IrStorage> {
    let mut storage = BTreeMap::new();
    for local in locals {
        if let Some(local_storage) = &local.storage {
            storage.insert(local.name.clone(), local_storage.clone());
        }
    }
    for block in blocks {
        infer_block_storage(block, &mut storage);
    }
    storage
}

fn infer_block_storage(block: &HirBlock, storage: &mut BTreeMap<String, IrStorage>) {
    for statement in &block.statements {
        infer_statement_storage(statement, storage);
    }
}

fn infer_statement_storage(statement: &HirStatement, storage: &mut BTreeMap<String, IrStorage>) {
    match statement {
        HirStatement::Assign {
            target: HirPlace::Named { name, .. },
            value,
        } => {
            if let Some(inferred) = storage_from_expression(value, storage)
                && should_record_inferred_storage(&inferred)
            {
                storage.entry(name.clone()).or_insert(inferred);
            }
        }
        HirStatement::If {
            then_body,
            else_body,
            ..
        } => {
            infer_block_storage(then_body, storage);
            if let Some(else_body) = else_body {
                infer_block_storage(else_body, storage);
            }
        }
        HirStatement::While { body, .. } | HirStatement::Loop { body } => {
            infer_block_storage(body, storage);
        }
        HirStatement::Switch { cases, default, .. } => {
            for case in cases {
                infer_block_storage(&case.body, storage);
            }
            if let Some(default) = default {
                infer_block_storage(default, storage);
            }
        }
        HirStatement::Assign { .. }
        | HirStatement::Expr(_)
        | HirStatement::Return { .. }
        | HirStatement::Goto(_)
        | HirStatement::Break
        | HirStatement::Continue
        | HirStatement::Label(_)
        | HirStatement::Trap
        | HirStatement::Unreachable => {}
    }
}

fn storage_from_expression(
    expression: &HirExpression,
    storage: &BTreeMap<String, IrStorage>,
) -> Option<IrStorage> {
    match expression {
        HirExpression::Value(HirValue::Named { name, .. }) => local_storage(storage, name),
        HirExpression::Load {
            address_space,
            address,
            ..
        } => {
            if let Some((base, offset)) = stack_location_from_address_space(address_space) {
                return Some(IrStorage::stack(
                    base,
                    offset + integer_expression_value(address).unwrap_or(0),
                    hir_type_bits(expression),
                ));
            }
            expression_text(address, storage)
                .map(|address| IrStorage::memory(address, hir_type_bits(expression)))
        }
        HirExpression::Deref { pointer, .. } => expression_text(pointer, storage)
            .map(|address| IrStorage::memory(address, hir_type_bits(expression))),
        HirExpression::Index { base, index, .. } => {
            let base = expression_text(base, storage)?;
            let index = expression_text(index, storage)?;
            Some(IrStorage::expression(
                format!("{base}[{index}]"),
                hir_type_bits(expression),
            ))
        }
        HirExpression::Binary { op, lhs, rhs, .. } => expression_text(expression, storage)
            .filter(|_| matches!(op, HirBinaryOperation::Add | HirBinaryOperation::Sub))
            .map(|text| IrStorage::expression(text, hir_type_bits(expression)))
            .or_else(|| {
                storage_from_expression(lhs, storage)
                    .or_else(|| storage_from_expression(rhs, storage))
            }),
        HirExpression::Cast { value, .. } => storage_from_expression(value, storage),
        HirExpression::Call {
            target,
            return_types,
            ..
        } => Some(IrStorage::call_return(
            call_target_name(target),
            0,
            return_types.first().map(type_bits).unwrap_or(0),
        )),
        HirExpression::Intrinsic {
            name, return_types, ..
        } => Some(IrStorage::call_return(
            Some(name.clone()),
            0,
            return_types.first().map(type_bits).unwrap_or(0),
        )),
        _ => None,
    }
}

fn should_record_inferred_storage(storage: &IrStorage) -> bool {
    match storage {
        IrStorage::Register { .. }
        | IrStorage::Stack { .. }
        | IrStorage::Memory { .. }
        | IrStorage::Expression { .. } => true,
        IrStorage::CallReturn { .. } => false,
    }
}

fn local_storage(storage: &BTreeMap<String, IrStorage>, name: &str) -> Option<IrStorage> {
    storage
        .get(name)
        .cloned()
        .or_else(|| storage.get(base_name(name)).cloned())
}

fn base_name(name: &str) -> &str {
    name.split_once('.').map(|(base, _)| base).unwrap_or(name)
}

fn expression_text(
    expression: &HirExpression,
    storage: &BTreeMap<String, IrStorage>,
) -> Option<String> {
    match expression {
        HirExpression::Value(HirValue::Named { name, .. }) => {
            local_storage(storage, name).and_then(|storage| storage_text(&storage))
        }
        HirExpression::Value(HirValue::Integer { value, .. }) => Some(format_integer(*value)),
        HirExpression::Value(HirValue::Null { .. }) => Some("0".to_string()),
        HirExpression::Binary { op, lhs, rhs, .. } => {
            let lhs = expression_text(lhs, storage)?;
            let rhs = expression_text(rhs, storage)?;
            match op {
                HirBinaryOperation::Add => Some(format_offset_expression(&lhs, &rhs, false)),
                HirBinaryOperation::Sub => Some(format_offset_expression(&lhs, &rhs, true)),
                _ => None,
            }
        }
        HirExpression::Cast { value, .. } => expression_text(value, storage),
        HirExpression::Load { address, .. } => {
            expression_text(address, storage).map(|address| format!("[{address}]"))
        }
        HirExpression::Deref { pointer, .. } => {
            expression_text(pointer, storage).map(|address| format!("[{address}]"))
        }
        _ => None,
    }
}

fn storage_text(storage: &IrStorage) -> Option<String> {
    match storage {
        IrStorage::Register { name, .. } => Some(name.clone()),
        IrStorage::Stack { base, offset, .. } => Some(format_memory_address(base, *offset)),
        IrStorage::Memory { address, .. } => Some(format!("[{address}]")),
        IrStorage::Expression { text, .. } => Some(text.clone()),
        IrStorage::CallReturn {
            target: Some(target),
            ..
        } => Some(format!("{} result", display_symbol_name(target))),
        IrStorage::CallReturn { .. } => Some("call result".to_string()),
    }
}

fn format_memory_address(base: &str, offset: i64) -> String {
    if offset == 0 {
        base.to_string()
    } else if offset < 0 {
        format!("{base}-{:x}h", offset.unsigned_abs())
    } else {
        format!("{base}+{offset:x}h")
    }
}

fn format_offset_expression(lhs: &str, rhs: &str, subtract: bool) -> String {
    if rhs == "0" {
        return lhs.to_string();
    }
    if let Some(rhs) = rhs.strip_prefix('-') {
        let op = if subtract { "+" } else { "-" };
        return format!("{lhs}{op}{rhs}");
    }
    let op = if subtract { "-" } else { "+" };
    format!("{lhs}{op}{rhs}")
}

fn format_integer(value: i128) -> String {
    if value < 0 {
        format!("-{:x}h", value.unsigned_abs())
    } else if value >= 10 {
        format!("{value:x}h")
    } else {
        value.to_string()
    }
}

fn call_target_name(target: &HirTarget) -> Option<String> {
    match target {
        HirTarget::Direct(name) => Some(name.clone()),
        HirTarget::Indirect(_) => None,
    }
}

fn display_symbol_name(name: &str) -> &str {
    name.rsplit_once('!')
        .map(|(_, symbol)| symbol)
        .unwrap_or(name)
}

fn stack_location_from_address_space(
    address_space: &HirAddressSpace,
) -> Option<(&'static str, i64)> {
    match address_space {
        HirAddressSpace::Local { name } | HirAddressSpace::Spill { name } => {
            parse_stack_slot_suffix(name).map(|offset| ("rbp", -offset))
        }
        HirAddressSpace::Argument { name } | HirAddressSpace::Incoming { name } => {
            parse_stack_slot_suffix(name).map(|offset| ("rsp", offset))
        }
        HirAddressSpace::SavedFrame { .. } | HirAddressSpace::ReturnAddress { .. } => {
            Some(("rsp", 0))
        }
        _ => None,
    }
}

fn hir_type_bits(expression: &HirExpression) -> u16 {
    match expression {
        HirExpression::Load { ty, .. } => type_bits(ty),
        _ => 0,
    }
}

fn type_bits(ty: &crate::ir::hir::HirType) -> u16 {
    match ty {
        crate::ir::hir::HirType::Integer(bits) | crate::ir::hir::HirType::Float(bits) => *bits,
        crate::ir::hir::HirType::Pointer { .. } => 64,
        _ => 0,
    }
}

fn parse_stack_slot_suffix(name: &str) -> Option<i64> {
    let digits = name.strip_prefix('m').unwrap_or(name);
    digits.parse::<i64>().ok()
}

fn integer_expression_value(expression: &HirExpression) -> Option<i64> {
    match expression {
        HirExpression::Value(HirValue::Integer { value, .. }) => i64::try_from(*value).ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::hir::{HirBlock, HirType};

    #[test]
    fn infers_stack_storage_for_local_stack_loads() {
        let block = HirBlock {
            statements: vec![HirStatement::Assign {
                target: HirPlace::Named {
                    name: "load0".to_string(),
                    ty: HirType::integer(64),
                },
                value: HirExpression::Load {
                    address_space: HirAddressSpace::Local {
                        name: "m20".to_string(),
                    },
                    address: Box::new(HirExpression::Value(HirValue::Integer {
                        value: 0,
                        bits: 64,
                    })),
                    ty: HirType::integer(64),
                },
            }],
        };

        let storage = infer_local_storage(&[block]);
        assert_eq!(
            storage.get("load0"),
            Some(&IrStorage::stack("rbp", -20, 64))
        );
    }

    #[test]
    fn infers_stack_storage_for_incoming_stack_loads() {
        let block = HirBlock {
            statements: vec![HirStatement::Assign {
                target: HirPlace::Named {
                    name: "arg_load".to_string(),
                    ty: HirType::integer(32),
                },
                value: HirExpression::Load {
                    address_space: HirAddressSpace::Incoming {
                        name: "32".to_string(),
                    },
                    address: Box::new(HirExpression::Value(HirValue::Integer {
                        value: 8,
                        bits: 64,
                    })),
                    ty: HirType::integer(32),
                },
            }],
        };

        let storage = infer_local_storage(&[block]);
        assert_eq!(
            storage.get("arg_load"),
            Some(&IrStorage::stack("rsp", 40, 32))
        );
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct AstModule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub functions: Vec<AstFunction>,
}

impl AstModule {
    pub fn from_hir(hir: &HirModule) -> Self {
        Self {
            name: hir.name.clone(),
            functions: hir.functions.iter().map(AstFunction::from_hir).collect(),
        }
    }

    pub fn optimize(&mut self) {
        optimize_ast_module(self);
    }

    pub fn c(&self) -> String {
        format_c_module(self)
    }

    pub fn print_c(&self) {
        println!("{}", self.c());
    }

    pub fn text(&self) -> String {
        self.c()
    }

    pub fn print(&self) {
        self.print_c();
    }
}
