use super::block::AstBlock;
use super::c::{format_c_function, format_c_module};
use super::optimizers::{optimize_ast_function, optimize_ast_module};
use super::statement::{AstLocal, AstParameter, AstStackStorage};
use crate::ir::hir::{
    HirAddressSpace, HirBlock, HirExpression, HirFunction, HirModule, HirPlace, HirStatement,
    HirValue,
};
use crate::ir::lir::LirAbi;
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
        let stack_storage = infer_local_stack_storage(&hir.blocks);
        let mut locals = hir
            .locals
            .iter()
            .map(AstLocal::from_hir)
            .collect::<Vec<_>>();
        for local in &mut locals {
            if let Some(storage) = stack_storage.get(&local.name) {
                local.stack = Some(storage.clone());
            }
        }
        Self {
            name: hir.name.clone(),
            abi: hir.abi.clone(),
            parameters: hir.parameters.iter().map(AstParameter::from_hir).collect(),
            returns: hir.returns.clone(),
            locals,
            blocks: hir.blocks.iter().map(AstBlock::from_hir).collect(),
        }
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

fn infer_local_stack_storage(blocks: &[HirBlock]) -> BTreeMap<String, AstStackStorage> {
    let mut storage = BTreeMap::new();
    for block in blocks {
        infer_block_stack_storage(block, &mut storage);
    }
    storage
}

fn infer_block_stack_storage(block: &HirBlock, storage: &mut BTreeMap<String, AstStackStorage>) {
    for statement in &block.statements {
        infer_statement_stack_storage(statement, storage);
    }
}

fn infer_statement_stack_storage(
    statement: &HirStatement,
    storage: &mut BTreeMap<String, AstStackStorage>,
) {
    match statement {
        HirStatement::Assign {
            target: HirPlace::Named { name, .. },
            value,
        } => {
            if let Some(stack) = stack_storage_from_expression(value) {
                storage.entry(name.clone()).or_insert(stack);
            }
        }
        HirStatement::If {
            then_body,
            else_body,
            ..
        } => {
            infer_block_stack_storage(then_body, storage);
            if let Some(else_body) = else_body {
                infer_block_stack_storage(else_body, storage);
            }
        }
        HirStatement::While { body, .. } | HirStatement::Loop { body } => {
            infer_block_stack_storage(body, storage);
        }
        HirStatement::Switch { cases, default, .. } => {
            for case in cases {
                infer_block_stack_storage(&case.body, storage);
            }
            if let Some(default) = default {
                infer_block_stack_storage(default, storage);
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

fn stack_storage_from_expression(expression: &HirExpression) -> Option<AstStackStorage> {
    let HirExpression::Load {
        address_space,
        address,
        ..
    } = expression
    else {
        return None;
    };

    let base = stack_offset_from_address_space(address_space)?;
    Some(AstStackStorage::new(
        base + integer_expression_value(address).unwrap_or(0),
    ))
}

fn stack_offset_from_address_space(address_space: &HirAddressSpace) -> Option<i64> {
    match address_space {
        HirAddressSpace::Local { name } | HirAddressSpace::Spill { name } => {
            parse_stack_slot_suffix(name).map(|offset| -offset)
        }
        HirAddressSpace::Argument { name } | HirAddressSpace::Incoming { name } => {
            parse_stack_slot_suffix(name)
        }
        HirAddressSpace::SavedFrame { .. } | HirAddressSpace::ReturnAddress { .. } => Some(0),
        _ => None,
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

        let storage = infer_local_stack_storage(&[block]);
        assert_eq!(storage.get("load0"), Some(&AstStackStorage::new(-20)));
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

        let storage = infer_local_stack_storage(&[block]);
        assert_eq!(storage.get("arg_load"), Some(&AstStackStorage::new(40)));
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
