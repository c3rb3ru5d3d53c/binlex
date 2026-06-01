use super::block::AstBlock;
use super::c::{format_c_function, format_c_function_with_image, format_c_module};
use super::expression::AstExpression;
use super::optimizers::{optimize_ast_function, optimize_ast_module};
use super::place::AstPlace;
use super::statement::{AstLocal, AstParameter, AstStatement};
use super::target::AstTarget;
use super::value::AstValue;
use crate::formats::Image;
use crate::ir::hir::{
    HirAddressSpace, HirBinaryOperation, HirBlock, HirExpression, HirFunction, HirModule, HirPlace,
    HirStatement, HirTarget, HirValue,
};
use crate::ir::lir::LirAbi;
use crate::ir::storage::IrStorage;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const STACK_ARGUMENT_BASE_OFFSET: i128 = 0x20;
const FRAME_ARGUMENT_BASE_OFFSET: i128 = 0x8;
const STACK_ARGUMENT_SLOT_SIZE: i128 = 8;
const MAX_PROMOTED_STACK_ARGUMENTS: usize = 12;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum StackParameterSpace {
    Incoming,
    Argument,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct StackParameterSlot {
    space: StackParameterSpace,
    offset: i128,
}

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
        let promoted_parameters = promote_incoming_stack_parameters(&mut function);
        optimize_ast_function(&mut function);
        remove_unused_promoted_parameters(&mut function, &promoted_parameters);
        function
    }

    pub fn optimize(&mut self) {
        optimize_ast_function(self);
    }

    pub fn c(&self) -> String {
        format_c_function(self)
    }

    pub fn c_with_image(&self, image: &Image) -> String {
        format_c_function_with_image(self, image)
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

fn promote_incoming_stack_parameters(function: &mut AstFunction) -> BTreeSet<String> {
    let mut reads = BTreeMap::<StackParameterSlot, super::kind::AstType>::new();
    let mut stores = BTreeSet::<StackParameterSlot>::new();
    let mut promoted_names = BTreeSet::new();
    let parameter_limit = function.parameters.len();

    for block in &function.blocks {
        collect_incoming_stack_slots(block, &mut reads, &mut stores);
    }

    let mut existing = function
        .parameters
        .iter()
        .map(|parameter| parameter.name.clone())
        .collect::<BTreeSet<_>>();
    let mut promoted = BTreeMap::<StackParameterSlot, String>::new();
    let promotable_offsets = promotable_incoming_stack_offsets(&reads, &stores);

    for (slot, ty) in reads {
        if !promotable_offsets.contains(&slot) {
            continue;
        }
        if parameter_limit > 0
            && let Some(index) = stack_parameter_index(slot)
            && index >= parameter_limit
        {
            continue;
        }
        let name = stack_parameter_name(slot);
        if !existing.contains(&name) {
            existing.insert(name.clone());
            function.parameters.push(AstParameter {
                name: name.clone(),
                ty,
            });
        }
        promoted_names.insert(name.clone());
        promoted.insert(slot, name);
    }

    if promoted.is_empty() {
        return promoted_names;
    }

    for block in &mut function.blocks {
        rewrite_incoming_stack_parameters(block, &promoted);
    }

    promoted_names
}

fn promotable_incoming_stack_offsets(
    reads: &BTreeMap<StackParameterSlot, super::kind::AstType>,
    stores: &BTreeSet<StackParameterSlot>,
) -> BTreeSet<StackParameterSlot> {
    let mut offsets = BTreeSet::new();

    for index in 0..MAX_PROMOTED_STACK_ARGUMENTS {
        for slot in [
            StackParameterSlot {
                space: StackParameterSpace::Incoming,
                offset: STACK_ARGUMENT_BASE_OFFSET + ((index as i128) * STACK_ARGUMENT_SLOT_SIZE),
            },
            StackParameterSlot {
                space: StackParameterSpace::Argument,
                offset: FRAME_ARGUMENT_BASE_OFFSET + ((index as i128) * STACK_ARGUMENT_SLOT_SIZE),
            },
        ] {
            if !stores.contains(&slot) && reads.contains_key(&slot) {
                offsets.insert(slot);
            }
        }
    }

    offsets
}

fn remove_unused_promoted_parameters(function: &mut AstFunction, promoted: &BTreeSet<String>) {
    if promoted.is_empty() {
        return;
    }

    let mut used = BTreeSet::new();
    for block in &function.blocks {
        collect_named_value_uses(block, &mut used);
    }

    function
        .parameters
        .retain(|parameter| !promoted.contains(&parameter.name) || used.contains(&parameter.name));
}

fn collect_named_value_uses(block: &AstBlock, used: &mut BTreeSet<String>) {
    for statement in &block.statements {
        collect_named_value_uses_in_statement(statement, used);
    }
}

fn collect_named_value_uses_in_statement(statement: &AstStatement, used: &mut BTreeSet<String>) {
    match statement {
        AstStatement::Assign { target, value } => {
            collect_named_value_uses_in_place(target, used);
            collect_named_value_uses_in_expression(value, used);
        }
        AstStatement::Expr(value) => collect_named_value_uses_in_expression(value, used),
        AstStatement::If {
            condition,
            then_body,
            else_body,
        } => {
            collect_named_value_uses_in_expression(condition, used);
            collect_named_value_uses(then_body, used);
            if let Some(else_body) = else_body {
                collect_named_value_uses(else_body, used);
            }
        }
        AstStatement::While { condition, body } => {
            collect_named_value_uses_in_expression(condition, used);
            collect_named_value_uses(body, used);
        }
        AstStatement::Loop { body } => collect_named_value_uses(body, used),
        AstStatement::Switch {
            value,
            cases,
            default,
        } => {
            collect_named_value_uses_in_expression(value, used);
            for case in cases {
                collect_named_value_uses(&case.body, used);
            }
            if let Some(default) = default {
                collect_named_value_uses(default, used);
            }
        }
        AstStatement::Return { values } => {
            for value in values {
                collect_named_value_uses_in_expression(value, used);
            }
        }
        AstStatement::Goto(AstTarget::Indirect(value)) => {
            collect_named_value_uses_in_expression(value, used);
        }
        AstStatement::Break
        | AstStatement::Continue
        | AstStatement::Label(_)
        | AstStatement::Goto(AstTarget::Direct(_))
        | AstStatement::Trap
        | AstStatement::Unreachable => {}
    }
}

fn collect_named_value_uses_in_expression(expression: &AstExpression, used: &mut BTreeSet<String>) {
    match expression {
        AstExpression::Value(AstValue::Named { name, .. }) => {
            used.insert(name.clone());
        }
        AstExpression::Unary { value, .. }
        | AstExpression::Extract { value, .. }
        | AstExpression::Cast { value, .. } => collect_named_value_uses_in_expression(value, used),
        AstExpression::Binary { lhs, rhs, .. }
        | AstExpression::Compare { lhs, rhs, .. }
        | AstExpression::FloatCompare { lhs, rhs, .. } => {
            collect_named_value_uses_in_expression(lhs, used);
            collect_named_value_uses_in_expression(rhs, used);
        }
        AstExpression::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            collect_named_value_uses_in_expression(condition, used);
            collect_named_value_uses_in_expression(when_true, used);
            collect_named_value_uses_in_expression(when_false, used);
        }
        AstExpression::Concat { parts, .. } => {
            for part in parts {
                collect_named_value_uses_in_expression(part, used);
            }
        }
        AstExpression::Load { address, .. } => {
            collect_named_value_uses_in_expression(address, used)
        }
        AstExpression::Call {
            target, arguments, ..
        } => {
            collect_named_value_uses_in_target(target, used);
            for argument in arguments {
                collect_named_value_uses_in_expression(argument, used);
            }
        }
        AstExpression::Intrinsic { arguments, .. } => {
            for argument in arguments {
                collect_named_value_uses_in_expression(argument, used);
            }
        }
        AstExpression::AddressOf { place, .. } => collect_named_value_uses_in_place(place, used),
        AstExpression::Deref { pointer, .. } => {
            collect_named_value_uses_in_expression(pointer, used)
        }
        AstExpression::Index { base, index, .. } => {
            collect_named_value_uses_in_expression(base, used);
            collect_named_value_uses_in_expression(index, used);
        }
        AstExpression::Value(_) => {}
    }
}

fn collect_named_value_uses_in_place(place: &AstPlace, used: &mut BTreeSet<String>) {
    match place {
        AstPlace::Deref { pointer, .. }
        | AstPlace::Memory {
            address: pointer, ..
        } => {
            collect_named_value_uses_in_expression(pointer, used);
        }
        AstPlace::Index { base, index, .. } => {
            collect_named_value_uses_in_expression(base, used);
            collect_named_value_uses_in_expression(index, used);
        }
        AstPlace::Named { .. } => {}
    }
}

fn collect_named_value_uses_in_target(target: &AstTarget, used: &mut BTreeSet<String>) {
    if let AstTarget::Indirect(expression) = target {
        collect_named_value_uses_in_expression(expression, used);
    }
}

fn collect_incoming_stack_slots(
    block: &AstBlock,
    reads: &mut BTreeMap<StackParameterSlot, super::kind::AstType>,
    stores: &mut BTreeSet<StackParameterSlot>,
) {
    for statement in &block.statements {
        collect_incoming_stack_slots_in_statement(statement, reads, stores);
    }
}

fn collect_incoming_stack_slots_in_statement(
    statement: &AstStatement,
    reads: &mut BTreeMap<StackParameterSlot, super::kind::AstType>,
    stores: &mut BTreeSet<StackParameterSlot>,
) {
    match statement {
        AstStatement::Assign { target, value } => {
            collect_incoming_stack_slots_in_place(target, reads, stores);
            collect_incoming_stack_slots_in_expression(value, reads, stores);
        }
        AstStatement::Expr(value) => {
            collect_incoming_stack_slots_in_expression(value, reads, stores)
        }
        AstStatement::If {
            condition,
            then_body,
            else_body,
        } => {
            collect_incoming_stack_slots_in_expression(condition, reads, stores);
            collect_incoming_stack_slots(then_body, reads, stores);
            if let Some(else_body) = else_body {
                collect_incoming_stack_slots(else_body, reads, stores);
            }
        }
        AstStatement::While { condition, body } => {
            collect_incoming_stack_slots_in_expression(condition, reads, stores);
            collect_incoming_stack_slots(body, reads, stores);
        }
        AstStatement::Loop { body } => collect_incoming_stack_slots(body, reads, stores),
        AstStatement::Switch {
            value,
            cases,
            default,
        } => {
            collect_incoming_stack_slots_in_expression(value, reads, stores);
            for case in cases {
                collect_incoming_stack_slots(&case.body, reads, stores);
            }
            if let Some(default) = default {
                collect_incoming_stack_slots(default, reads, stores);
            }
        }
        AstStatement::Return { values } => {
            for value in values {
                collect_incoming_stack_slots_in_expression(value, reads, stores);
            }
        }
        AstStatement::Goto(AstTarget::Indirect(value)) => {
            collect_incoming_stack_slots_in_expression(value, reads, stores);
        }
        AstStatement::Break
        | AstStatement::Continue
        | AstStatement::Label(_)
        | AstStatement::Goto(AstTarget::Direct(_))
        | AstStatement::Trap
        | AstStatement::Unreachable => {}
    }
}

fn collect_incoming_stack_slots_in_expression(
    expression: &AstExpression,
    reads: &mut BTreeMap<StackParameterSlot, super::kind::AstType>,
    stores: &mut BTreeSet<StackParameterSlot>,
) {
    match expression {
        AstExpression::Load {
            address_space,
            address,
            ty,
        } => {
            if let Some(slot) = stack_parameter_slot(address_space, address) {
                reads.entry(slot).or_insert_with(|| ty.clone());
            }
            collect_incoming_stack_slots_in_expression(address, reads, stores);
        }
        AstExpression::Unary { value, .. }
        | AstExpression::Extract { value, .. }
        | AstExpression::Cast { value, .. } => {
            collect_incoming_stack_slots_in_expression(value, reads, stores);
        }
        AstExpression::Binary { lhs, rhs, .. }
        | AstExpression::Compare { lhs, rhs, .. }
        | AstExpression::FloatCompare { lhs, rhs, .. } => {
            collect_incoming_stack_slots_in_expression(lhs, reads, stores);
            collect_incoming_stack_slots_in_expression(rhs, reads, stores);
        }
        AstExpression::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            collect_incoming_stack_slots_in_expression(condition, reads, stores);
            collect_incoming_stack_slots_in_expression(when_true, reads, stores);
            collect_incoming_stack_slots_in_expression(when_false, reads, stores);
        }
        AstExpression::Concat { parts, .. } => {
            for part in parts {
                collect_incoming_stack_slots_in_expression(part, reads, stores);
            }
        }
        AstExpression::Call {
            target, arguments, ..
        } => {
            collect_incoming_stack_slots_in_target(target, reads, stores);
            for argument in arguments {
                collect_incoming_stack_slots_in_expression(argument, reads, stores);
            }
        }
        AstExpression::Intrinsic { arguments, .. } => {
            for argument in arguments {
                collect_incoming_stack_slots_in_expression(argument, reads, stores);
            }
        }
        AstExpression::AddressOf { place, .. } => {
            collect_incoming_stack_slots_in_place(place, reads, stores);
        }
        AstExpression::Deref { pointer, .. } => {
            collect_incoming_stack_slots_in_expression(pointer, reads, stores);
        }
        AstExpression::Index { base, index, .. } => {
            collect_incoming_stack_slots_in_expression(base, reads, stores);
            collect_incoming_stack_slots_in_expression(index, reads, stores);
        }
        AstExpression::Value(_) => {}
    }
}

fn collect_incoming_stack_slots_in_place(
    place: &AstPlace,
    reads: &mut BTreeMap<StackParameterSlot, super::kind::AstType>,
    stores: &mut BTreeSet<StackParameterSlot>,
) {
    match place {
        AstPlace::Memory {
            address_space,
            address,
            ..
        } => {
            if let Some(slot) = stack_parameter_slot(address_space, address) {
                stores.insert(slot);
            }
            collect_incoming_stack_slots_in_expression(address, reads, stores);
        }
        AstPlace::Deref { pointer, .. } => {
            collect_incoming_stack_slots_in_expression(pointer, reads, stores);
        }
        AstPlace::Index { base, index, .. } => {
            collect_incoming_stack_slots_in_expression(base, reads, stores);
            collect_incoming_stack_slots_in_expression(index, reads, stores);
        }
        AstPlace::Named { .. } => {}
    }
}

fn collect_incoming_stack_slots_in_target(
    target: &AstTarget,
    reads: &mut BTreeMap<StackParameterSlot, super::kind::AstType>,
    stores: &mut BTreeSet<StackParameterSlot>,
) {
    if let AstTarget::Indirect(expression) = target {
        collect_incoming_stack_slots_in_expression(expression, reads, stores);
    }
}

fn rewrite_incoming_stack_parameters(
    block: &mut AstBlock,
    promoted: &BTreeMap<StackParameterSlot, String>,
) {
    for statement in &mut block.statements {
        rewrite_incoming_stack_parameters_in_statement(statement, promoted);
    }
}

fn rewrite_incoming_stack_parameters_in_statement(
    statement: &mut AstStatement,
    promoted: &BTreeMap<StackParameterSlot, String>,
) {
    match statement {
        AstStatement::Assign { target, value } => {
            rewrite_incoming_stack_parameters_in_place(target, promoted);
            rewrite_incoming_stack_parameters_in_expression(value, promoted);
        }
        AstStatement::Expr(value) => {
            rewrite_incoming_stack_parameters_in_expression(value, promoted)
        }
        AstStatement::If {
            condition,
            then_body,
            else_body,
        } => {
            rewrite_incoming_stack_parameters_in_expression(condition, promoted);
            rewrite_incoming_stack_parameters(then_body, promoted);
            if let Some(else_body) = else_body {
                rewrite_incoming_stack_parameters(else_body, promoted);
            }
        }
        AstStatement::While { condition, body } => {
            rewrite_incoming_stack_parameters_in_expression(condition, promoted);
            rewrite_incoming_stack_parameters(body, promoted);
        }
        AstStatement::Loop { body } => rewrite_incoming_stack_parameters(body, promoted),
        AstStatement::Switch {
            value,
            cases,
            default,
        } => {
            rewrite_incoming_stack_parameters_in_expression(value, promoted);
            for case in cases {
                rewrite_incoming_stack_parameters(&mut case.body, promoted);
            }
            if let Some(default) = default {
                rewrite_incoming_stack_parameters(default, promoted);
            }
        }
        AstStatement::Return { values } => {
            for value in values {
                rewrite_incoming_stack_parameters_in_expression(value, promoted);
            }
        }
        AstStatement::Goto(AstTarget::Indirect(value)) => {
            rewrite_incoming_stack_parameters_in_expression(value, promoted);
        }
        AstStatement::Break
        | AstStatement::Continue
        | AstStatement::Label(_)
        | AstStatement::Goto(AstTarget::Direct(_))
        | AstStatement::Trap
        | AstStatement::Unreachable => {}
    }
}

fn rewrite_incoming_stack_parameters_in_expression(
    expression: &mut AstExpression,
    promoted: &BTreeMap<StackParameterSlot, String>,
) {
    match expression {
        AstExpression::Load {
            address_space,
            address,
            ty,
        } => {
            if let Some(slot) = stack_parameter_slot(address_space, address)
                && let Some(name) = promoted.get(&slot)
            {
                *expression = AstExpression::Value(AstValue::Named {
                    name: name.clone(),
                    ty: ty.clone(),
                });
                return;
            }
            rewrite_incoming_stack_parameters_in_expression(address, promoted);
        }
        AstExpression::Unary { value, .. }
        | AstExpression::Extract { value, .. }
        | AstExpression::Cast { value, .. } => {
            rewrite_incoming_stack_parameters_in_expression(value, promoted);
        }
        AstExpression::Binary { lhs, rhs, .. }
        | AstExpression::Compare { lhs, rhs, .. }
        | AstExpression::FloatCompare { lhs, rhs, .. } => {
            rewrite_incoming_stack_parameters_in_expression(lhs, promoted);
            rewrite_incoming_stack_parameters_in_expression(rhs, promoted);
        }
        AstExpression::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            rewrite_incoming_stack_parameters_in_expression(condition, promoted);
            rewrite_incoming_stack_parameters_in_expression(when_true, promoted);
            rewrite_incoming_stack_parameters_in_expression(when_false, promoted);
        }
        AstExpression::Concat { parts, .. } => {
            for part in parts {
                rewrite_incoming_stack_parameters_in_expression(part, promoted);
            }
        }
        AstExpression::Call {
            target, arguments, ..
        } => {
            rewrite_incoming_stack_parameters_in_target(target, promoted);
            for argument in arguments {
                rewrite_incoming_stack_parameters_in_expression(argument, promoted);
            }
        }
        AstExpression::Intrinsic { arguments, .. } => {
            for argument in arguments {
                rewrite_incoming_stack_parameters_in_expression(argument, promoted);
            }
        }
        AstExpression::AddressOf { place, .. } => {
            rewrite_incoming_stack_parameters_in_place(place, promoted);
        }
        AstExpression::Deref { pointer, .. } => {
            rewrite_incoming_stack_parameters_in_expression(pointer, promoted);
        }
        AstExpression::Index { base, index, .. } => {
            rewrite_incoming_stack_parameters_in_expression(base, promoted);
            rewrite_incoming_stack_parameters_in_expression(index, promoted);
        }
        AstExpression::Value(_) => {}
    }
}

fn rewrite_incoming_stack_parameters_in_place(
    place: &mut AstPlace,
    promoted: &BTreeMap<StackParameterSlot, String>,
) {
    match place {
        AstPlace::Memory { address, .. }
        | AstPlace::Deref {
            pointer: address, ..
        } => {
            rewrite_incoming_stack_parameters_in_expression(address, promoted);
        }
        AstPlace::Index { base, index, .. } => {
            rewrite_incoming_stack_parameters_in_expression(base, promoted);
            rewrite_incoming_stack_parameters_in_expression(index, promoted);
        }
        AstPlace::Named { .. } => {}
    }
}

fn rewrite_incoming_stack_parameters_in_target(
    target: &mut AstTarget,
    promoted: &BTreeMap<StackParameterSlot, String>,
) {
    if let AstTarget::Indirect(expression) = target {
        rewrite_incoming_stack_parameters_in_expression(expression, promoted);
    }
}

fn stack_parameter_slot(
    address_space: &HirAddressSpace,
    address: &AstExpression,
) -> Option<StackParameterSlot> {
    let (space, name) = match address_space {
        HirAddressSpace::Incoming { name } => (StackParameterSpace::Incoming, name),
        HirAddressSpace::Argument { name } => (StackParameterSpace::Argument, name),
        _ => return None,
    };
    let base = parse_incoming_stack_offset(name)?;
    let offset = match address {
        AstExpression::Value(AstValue::Integer { value, .. }) => *value,
        _ => return None,
    };
    Some(StackParameterSlot {
        space,
        offset: base + offset,
    })
}

fn parse_incoming_stack_offset(name: &str) -> Option<i128> {
    name.parse::<i128>().ok()
}

fn stack_parameter_name(slot: StackParameterSlot) -> String {
    let index = stack_parameter_index(slot).unwrap_or(0);
    format!("arg{index}")
}

fn stack_parameter_index(slot: StackParameterSlot) -> Option<usize> {
    let index = match slot.space {
        StackParameterSpace::Incoming => {
            4 + ((slot.offset - STACK_ARGUMENT_BASE_OFFSET) / STACK_ARGUMENT_SLOT_SIZE)
        }
        StackParameterSpace::Argument => {
            (slot.offset - FRAME_ARGUMENT_BASE_OFFSET) / STACK_ARGUMENT_SLOT_SIZE
        }
    };
    usize::try_from(index).ok()
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
