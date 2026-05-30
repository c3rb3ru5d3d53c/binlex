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

use crate::ir::lir::{
    Lir, LirAbi, LirAddressSpace, LirBlock as LirBasicBlock, LirCpu, LirEffect, LirExpression,
    LirFunction, LirLocation, LirOperationBinary, LirOperationCast, LirOperationCompare,
    LirOperationUnary, LirTerminator,
};
use crate::ir::mir::{
    MirAddressSpace, MirBlock, MirBlockParameter, MirControlTarget, MirFunction, MirOperation,
    MirOperationKind, MirTerminator, MirType, MirValue,
};
use crate::ir::mir::{MirCastOperation, MirCompareOperation, MirFloatCompareOperation};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::{Display, Formatter};

#[derive(Clone, Debug)]
pub struct MirLowerError {
    pub message: String,
}

impl Display for MirLowerError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for MirLowerError {}

#[derive(Default)]
struct LoweringContext {
    next_temp: usize,
    next_register: usize,
    next_flag: usize,
    location_names: BTreeMap<String, String>,
    abi: Option<LirAbi>,
}

impl LoweringContext {
    fn next_name(&mut self, prefix: &str) -> String {
        let name = format!("{prefix}_{}", self.next_temp);
        self.next_temp += 1;
        name
    }

    fn with_abi(abi: Option<&LirAbi>) -> Self {
        Self {
            abi: abi.cloned(),
            ..Self::default()
        }
    }

    fn location_name(&mut self, location: &LirLocation) -> String {
        let abi = self.abi.clone();
        self.location_name_with_abi(location, abi.as_ref())
    }

    fn location_name_with_abi(&mut self, location: &LirLocation, abi: Option<&LirAbi>) -> String {
        match location {
            LirLocation::Register { name, .. } => self.register_name_with_abi(name, abi),
            LirLocation::Flag { name, .. } => self.flag_name(name),
            LirLocation::IndexedMemory { name, .. } | LirLocation::StackMemory { name, .. } => {
                name.clone()
            }
            LirLocation::ProgramCounter { .. } => "pc".to_string(),
            LirLocation::Temporary { id, .. } => format!("tmp_{id}"),
            LirLocation::Memory { space, .. } => format!("mem_{:?}", space).to_lowercase(),
        }
    }

    fn register_name_with_abi(&mut self, raw_name: &str, abi: Option<&LirAbi>) -> String {
        if let Some(name) = canonical_register_role(raw_name, abi) {
            return name;
        }
        let key = abi
            .and_then(|abi| canonical_register_storage_name(&abi.cpu, raw_name))
            .unwrap_or_else(|| raw_name.to_string());
        if let Some(name) = self.location_names.get(&key) {
            return name.clone();
        }
        let name = format!("reg{}", self.next_register);
        self.next_register += 1;
        self.location_names.insert(key, name.clone());
        name
    }

    fn flag_name(&mut self, raw_name: &str) -> String {
        if let Some(name) = canonical_flag_name(raw_name) {
            return name;
        }
        let key = format!("flag:{raw_name}");
        if let Some(name) = self.location_names.get(&key) {
            return name.clone();
        }
        let name = format!("flag{}", self.next_flag);
        self.next_flag += 1;
        self.location_names.insert(key, name.clone());
        name
    }

    fn register_zero_extend_write_bits(&self, location: &LirLocation) -> Option<u16> {
        let LirLocation::Register { name, bits } = location else {
            return None;
        };
        let resolution = self.abi.as_ref()?.cpu.resolve_register(name)?;
        (resolution.zero_extend_on_write && resolution.storage_bits > *bits)
            .then_some(resolution.storage_bits)
    }
}

pub fn lower_lir_to_mir(
    name: Option<String>,
    lir: &LirFunction,
) -> Result<MirFunction, MirLowerError> {
    let mut mir = MirFunction::new(name);
    let explicit_abi = lir.abi.clone().or_else(|| {
        lir.instructions()
            .into_iter()
            .find_map(|instruction| instruction.abi.clone())
    });
    mir.abi = explicit_abi.clone().or_else(|| default_function_abi(lir));

    if lir.blocks.is_empty() || lir.blocks.iter().all(|block| block.instructions.is_empty()) {
        let mut block = MirBlock::new("entry".to_string());
        block.set_terminator(MirTerminator::Return { values: Vec::new() });
        mir.append_block(block);
        return Ok(mir);
    }

    let block_names = build_block_names(&lir.blocks);
    let mut address_to_block = HashMap::new();
    for (lir_block, block_name) in lir.blocks.iter().zip(block_names.iter()) {
        for semantic in &lir_block.instructions {
            if let Some(encoding) = semantic.encoding.as_ref() {
                address_to_block
                    .entry(encoding.address)
                    .or_insert_with(|| block_name.clone());
            }
        }
    }

    let mut context = LoweringContext::with_abi(mir.abi.as_ref());
    mir.entry_parameters =
        build_entry_parameters(lir, mir.abi.as_ref(), explicit_abi.is_some(), &mut context);

    for (index, lir_block) in lir.blocks.iter().enumerate() {
        if lir_block.instructions.is_empty() {
            continue;
        }
        mir.append_block(lower_lir_block_with_context(
            block_names[index].clone(),
            lir_block,
            mir.abi.as_ref(),
            index,
            &block_names,
            &address_to_block,
            &mut context,
        )?);
    }

    let entry_parameters = mir.entry_parameters.clone();
    if let Some(entry_block) = mir.blocks_mut().first_mut() {
        append_entry_parameters(entry_block, &entry_parameters);
    }

    Ok(mir)
}

pub fn materialize_entry_parameters(mir: &mut MirFunction) {
    let entry_parameters = mir.entry_parameters.clone();
    if let Some(entry_block) = mir.blocks_mut().first_mut() {
        append_entry_parameters(entry_block, &entry_parameters);
    }
}

pub fn lower_lir_block_to_mir(
    name: Option<String>,
    lir: &LirBasicBlock,
) -> Result<MirBlock, MirLowerError> {
    let block_name = name
        .or_else(|| lir.name.clone())
        .or_else(|| {
            lir.instructions.first().and_then(|semantic| {
                semantic
                    .encoding
                    .as_ref()
                    .map(|encoding| format!("block_{:x}", encoding.address))
            })
        })
        .unwrap_or_else(|| "block_0".to_string());

    let mut address_to_block = HashMap::new();
    for semantic in &lir.instructions {
        if let Some(encoding) = semantic.encoding.as_ref() {
            address_to_block
                .entry(encoding.address)
                .or_insert_with(|| block_name.clone());
        }
    }

    let block_names = vec![block_name.clone()];
    let mut context = LoweringContext::default();
    lower_lir_block_with_context(
        block_name,
        lir,
        None,
        0,
        &block_names,
        &address_to_block,
        &mut context,
    )
}

fn lower_lir_block_with_context(
    block_name: String,
    lir_block: &LirBasicBlock,
    function_abi: Option<&LirAbi>,
    index: usize,
    block_names: &[String],
    address_to_block: &HashMap<u64, String>,
    context: &mut LoweringContext,
) -> Result<MirBlock, MirLowerError> {
    if lir_block.instructions.is_empty() {
        return Err(MirLowerError {
            message: format!("cannot lower empty LIR block {block_name}"),
        });
    }

    let mut block = MirBlock::new(block_name);

    for (semantic_index, semantic) in lir_block.instructions.iter().enumerate() {
        for effect in &semantic.effects {
            lower_effect(effect, &mut block, context);
        }

        let is_last_instruction = semantic_index + 1 == lir_block.instructions.len();
        if !is_last_instruction
            && let LirTerminator::Call {
                target,
                does_return,
                ..
            } = &semantic.terminator
        {
            lower_call_operations(
                semantic,
                target,
                *does_return,
                function_abi,
                &mut block,
                context,
            );
            if matches!(does_return, Some(false)) {
                block.set_terminator(MirTerminator::Unreachable);
                return Ok(block);
            }
        }
    }

    let semantic = lir_block.instructions.last().expect("non-empty block");
    let terminator = lower_terminator(
        semantic,
        &semantic.terminator,
        function_abi,
        index,
        block_names,
        address_to_block,
        &mut block,
        context,
    );
    block.set_terminator(terminator);
    Ok(block)
}

fn lower_call_operations(
    semantic: &Lir,
    target: &LirExpression,
    does_return: Option<bool>,
    function_abi: Option<&LirAbi>,
    block: &mut MirBlock,
    context: &mut LoweringContext,
) {
    let (call_result, result_types, return_location) = if matches!(does_return, Some(false)) {
        (None, Vec::new(), None)
    } else {
        call_result_binding(semantic, context)
    };

    let arguments = call_argument_values(semantic, function_abi, block, context);
    let target = resolve_call_target(target, block, context);
    block.append_operation(MirOperation::new(
        call_result.clone(),
        MirOperationKind::Call {
            target,
            arguments,
            result_types: result_types.clone(),
            clobbers: Vec::new(),
            memory_effects: Vec::new(),
        },
    ));

    if let (Some(call_result), Some((location, ty))) = (call_result, return_location) {
        block.append_operation(MirOperation::new(
            Some(context.location_name(&location)),
            MirOperationKind::Copy {
                value: MirValue::named(call_result, ty.clone()),
                ty,
            },
        ));
    }
}

fn build_block_names(blocks: &[LirBasicBlock]) -> Vec<String> {
    let mut used = HashSet::new();
    let mut names = Vec::with_capacity(blocks.len());

    for (index, block) in blocks.iter().enumerate() {
        let base = block
            .name
            .clone()
            .or_else(|| {
                block.instructions.first().and_then(|semantic| {
                    semantic
                        .encoding
                        .as_ref()
                        .map(|encoding| format!("block_{:x}", encoding.address))
                })
            })
            .unwrap_or_else(|| format!("block_{index}"));

        let mut candidate = base.clone();
        let mut suffix = 1usize;
        while !used.insert(candidate.clone()) {
            candidate = format!("{base}_{suffix}");
            suffix += 1;
        }
        names.push(candidate);
    }

    names
}

fn lower_effect(effect: &LirEffect, block: &mut MirBlock, context: &mut LoweringContext) {
    match effect {
        LirEffect::Set { dst, expression } => match dst {
            LirLocation::Memory { space, addr, bits } => {
                let address = lower_expression(addr, block, context);
                let value = lower_expression(expression, block, context);
                block.append_operation(MirOperation::new(
                    None,
                    MirOperationKind::Store {
                        address_space: lower_address_space(space),
                        address,
                        value,
                        ty: mir_type_for_bits(*bits),
                    },
                ));
            }
            LirLocation::IndexedMemory { name, index, bits } => {
                let address = lower_expression(index, block, context);
                let value = lower_expression(expression, block, context);
                block.append_operation(MirOperation::new(
                    None,
                    MirOperationKind::Store {
                        address_space: MirAddressSpace::named(name.clone()),
                        address,
                        value,
                        ty: mir_type_for_bits(*bits),
                    },
                ));
            }
            LirLocation::StackMemory { name, offset, bits } => {
                let value = lower_expression(expression, block, context);
                block.append_operation(MirOperation::new(
                    None,
                    MirOperationKind::Store {
                        address_space: MirAddressSpace::named(name.clone()),
                        address: MirValue::integer(*offset as i128, 64),
                        value,
                        ty: mir_type_for_bits(*bits),
                    },
                ));
            }
            _ => {
                let value = lower_expression(expression, block, context);
                let result = context.location_name(dst);
                if let Some(storage_bits) = context.register_zero_extend_write_bits(dst) {
                    let ty = mir_type_for_bits(storage_bits);
                    let extended = context.next_name("zext");
                    block.append_operation(MirOperation::new(
                        Some(extended.clone()),
                        MirOperationKind::Cast {
                            op: MirCastOperation::ZeroExtend,
                            value,
                            ty: ty.clone(),
                        },
                    ));
                    block.append_operation(MirOperation::new(
                        Some(result),
                        MirOperationKind::Copy {
                            value: MirValue::named(extended, ty.clone()),
                            ty,
                        },
                    ));
                    return;
                }
                block.append_operation(MirOperation::new(
                    Some(result),
                    MirOperationKind::Copy {
                        value,
                        ty: mir_type_for_bits(dst.bits()),
                    },
                ));
            }
        },
        LirEffect::Store {
            space,
            addr,
            expression,
            bits,
        } => {
            let address = lower_expression(addr, block, context);
            let value = lower_expression(expression, block, context);
            block.append_operation(MirOperation::new(
                None,
                MirOperationKind::Store {
                    address_space: lower_address_space(space),
                    address,
                    value,
                    ty: mir_type_for_bits(*bits),
                },
            ));
        }
        LirEffect::MemoryCopy {
            src_space,
            src_addr,
            dst_space,
            dst_addr,
            count,
            element_bits,
            decrement,
        } => {
            let src_address = lower_expression(src_addr, block, context);
            let dst_address = lower_expression(dst_addr, block, context);
            let count = lower_expression(count, block, context);
            let decrement = lower_expression(decrement, block, context);
            block.append_operation(MirOperation::new(
                None,
                MirOperationKind::MemoryCopy {
                    src_space: lower_address_space(src_space),
                    src_address,
                    dst_space: lower_address_space(dst_space),
                    dst_address,
                    count,
                    element_bits: *element_bits,
                    decrement,
                },
            ));
        }
        LirEffect::Trap { kind } => {
            block.append_operation(MirOperation::new(
                None,
                MirOperationKind::Intrinsic {
                    name: format!("lir.trap.{kind:?}").to_lowercase(),
                    arguments: Vec::new(),
                    result_types: Vec::new(),
                },
            ));
        }
        LirEffect::Fence { kind } => {
            block.append_operation(MirOperation::new(
                None,
                MirOperationKind::Intrinsic {
                    name: format!("lir.fence.{kind:?}").to_lowercase(),
                    arguments: Vec::new(),
                    result_types: Vec::new(),
                },
            ));
        }
        LirEffect::Push { stack, expression } => {
            let value = lower_expression(expression, block, context);
            block.append_operation(MirOperation::new(
                None,
                MirOperationKind::Intrinsic {
                    name: format!("lir.push.{stack}"),
                    arguments: vec![value],
                    result_types: Vec::new(),
                },
            ));
        }
        LirEffect::Pop { stack, dst } => {
            block.append_operation(MirOperation::new(
                Some(context.location_name(dst)),
                MirOperationKind::Intrinsic {
                    name: format!("lir.pop.{stack}"),
                    arguments: Vec::new(),
                    result_types: vec![mir_type_for_bits(dst.bits())],
                },
            ));
        }
        LirEffect::Intrinsic {
            name,
            args,
            outputs,
        } => {
            let arguments = args
                .iter()
                .map(|arg| lower_expression(arg, block, context))
                .collect();
            let result_types = outputs
                .iter()
                .map(|location| mir_type_for_bits(location.bits()))
                .collect();
            let result = outputs
                .first()
                .map(|location| context.location_name(location));
            block.append_operation(MirOperation::new(
                result,
                MirOperationKind::Intrinsic {
                    name: name.clone(),
                    arguments,
                    result_types,
                },
            ));
        }
        other => {
            block.append_operation(MirOperation::new(
                None,
                MirOperationKind::Intrinsic {
                    name: format!("lir.effect.{:?}", other.kind()).to_lowercase(),
                    arguments: Vec::new(),
                    result_types: Vec::new(),
                },
            ));
        }
    }
}

fn lower_terminator(
    semantic: &Lir,
    terminator: &LirTerminator,
    function_abi: Option<&LirAbi>,
    index: usize,
    block_names: &[String],
    address_to_block: &HashMap<u64, String>,
    block: &mut MirBlock,
    context: &mut LoweringContext,
) -> MirTerminator {
    match terminator {
        LirTerminator::FallThrough => {
            if let Some(next) = block_names.get(index + 1) {
                MirTerminator::Jump {
                    target: MirControlTarget::direct(next.clone()),
                    arguments: Vec::new(),
                }
            } else {
                MirTerminator::Return { values: Vec::new() }
            }
        }
        LirTerminator::Jump { target } => MirTerminator::Jump {
            target: resolve_block_target(target, address_to_block, block, context),
            arguments: Vec::new(),
        },
        LirTerminator::Branch {
            condition,
            true_target,
            false_target,
        } => MirTerminator::CondBr {
            condition: lower_expression(condition, block, context),
            then_target: resolve_block_target(true_target, address_to_block, block, context),
            then_arguments: Vec::new(),
            else_target: resolve_block_target(false_target, address_to_block, block, context),
            else_arguments: Vec::new(),
        },
        LirTerminator::Call {
            target,
            return_target,
            does_return,
        } => {
            lower_call_operations(semantic, target, *does_return, function_abi, block, context);

            if matches!(does_return, Some(false)) {
                MirTerminator::Unreachable
            } else if let Some(return_target) = return_target.as_ref() {
                MirTerminator::Jump {
                    target: resolve_block_target(return_target, address_to_block, block, context),
                    arguments: Vec::new(),
                }
            } else {
                MirTerminator::Return { values: Vec::new() }
            }
        }
        LirTerminator::Return { expression } => {
            let values = expression
                .as_ref()
                .map(|expression| vec![lower_expression(expression, block, context)])
                .unwrap_or_default();
            MirTerminator::Return { values }
        }
        LirTerminator::Unreachable => MirTerminator::Unreachable,
        LirTerminator::Trap => MirTerminator::Trap,
    }
}

fn lower_expression(
    expression: &LirExpression,
    block: &mut MirBlock,
    context: &mut LoweringContext,
) -> MirValue {
    match expression {
        LirExpression::Const { value, bits } => MirValue::integer(*value as i128, *bits),
        LirExpression::Function { name, bits } | LirExpression::DataAddress { name, bits } => {
            MirValue::named(name.clone(), mir_type_for_bits(*bits))
        }
        LirExpression::AddressOf { location, bits } => MirValue::named(
            format!("addr_of_{}", context.location_name(location)),
            mir_type_for_bits(*bits),
        ),
        LirExpression::Read(location) => MirValue::named(
            context.location_name(location),
            mir_type_for_bits(location.bits()),
        ),
        LirExpression::Load { space, addr, bits } => {
            let address = lower_expression(addr, block, context);
            let ty = mir_type_for_bits(*bits);
            let result = context.next_name("load");
            block.append_operation(MirOperation::new(
                Some(result.clone()),
                MirOperationKind::Load {
                    address_space: lower_address_space(space),
                    address,
                    ty: ty.clone(),
                },
            ));
            MirValue::named(result, ty)
        }
        LirExpression::Unary { op, arg, bits } => {
            lower_unary_expression(*op, arg, *bits, block, context)
        }
        LirExpression::Binary {
            op,
            left,
            right,
            bits,
        } => lower_binary_expression(*op, left, right, *bits, block, context),
        LirExpression::Cast { op, arg, bits } => {
            lower_cast_expression(*op, arg, *bits, block, context)
        }
        LirExpression::Compare {
            op,
            left,
            right,
            bits,
        } => lower_compare_expression(*op, left, right, *bits, block, context),
        LirExpression::Select {
            condition,
            when_true,
            when_false,
            bits,
        } => {
            let condition = lower_expression(condition, block, context);
            let when_true = lower_expression(when_true, block, context);
            let when_false = lower_expression(when_false, block, context);
            let ty = mir_type_for_bits(*bits);
            let result = context.next_name("select");
            block.append_operation(MirOperation::new(
                Some(result.clone()),
                MirOperationKind::Select {
                    condition,
                    when_true,
                    when_false,
                    ty: ty.clone(),
                },
            ));
            MirValue::named(result, ty)
        }
        LirExpression::Concat { parts, bits } => {
            let parts = parts
                .iter()
                .map(|part| lower_expression(part, block, context))
                .collect::<Vec<_>>();
            let ty = mir_type_for_bits(*bits);
            let result = context.next_name("concat");
            block.append_operation(MirOperation::new(
                Some(result.clone()),
                MirOperationKind::Concat {
                    parts,
                    ty: ty.clone(),
                },
            ));
            MirValue::named(result, ty)
        }
        LirExpression::Intrinsic { name, args, bits } => {
            let ty = mir_type_for_bits(*bits);
            let result = context.next_name("expr");
            let arguments = args
                .iter()
                .map(|arg| lower_expression(arg, block, context))
                .collect();
            block.append_operation(MirOperation::new(
                Some(result.clone()),
                MirOperationKind::Intrinsic {
                    name: name.clone(),
                    arguments,
                    result_types: vec![ty.clone()],
                },
            ));
            MirValue::named(result, ty)
        }
        LirExpression::Extract { arg, lsb, bits } => {
            let value = lower_expression(arg, block, context);
            let ty = mir_type_for_bits(*bits);
            let result = context.next_name("extract");
            block.append_operation(MirOperation::new(
                Some(result.clone()),
                MirOperationKind::Extract {
                    value,
                    lsb: *lsb,
                    ty: ty.clone(),
                },
            ));
            MirValue::named(result, ty)
        }
        LirExpression::Undefined { bits } | LirExpression::Poison { bits } => {
            MirValue::undef(mir_type_for_bits(*bits))
        }
        LirExpression::Null { bits } => MirValue::null(mir_type_for_bits(*bits)),
        other => {
            let ty = mir_type_for_expression(other);
            let result = context.next_name("expr");
            let arguments = expression_arguments(other)
                .into_iter()
                .map(|arg| lower_expression(arg, block, context))
                .collect();
            block.append_operation(MirOperation::new(
                Some(result.clone()),
                MirOperationKind::Intrinsic {
                    name: format!("lir.expr.{:?}", other.kind()).to_lowercase(),
                    arguments,
                    result_types: vec![ty.clone()],
                },
            ));
            MirValue::named(result, ty)
        }
    }
}

fn lower_unary_expression(
    op: LirOperationUnary,
    arg: &LirExpression,
    bits: u16,
    block: &mut MirBlock,
    context: &mut LoweringContext,
) -> MirValue {
    let value = lower_expression(arg, block, context);
    let ty = mir_type_for_bits(bits);
    let result = context.next_name("unary");

    let kind = match op {
        LirOperationUnary::Not => MirOperationKind::Not {
            value,
            ty: ty.clone(),
        },
        LirOperationUnary::Neg => MirOperationKind::Neg {
            value,
            ty: ty.clone(),
        },
        LirOperationUnary::PopCount => MirOperationKind::Popcount {
            value,
            ty: ty.clone(),
        },
        LirOperationUnary::CountLeadingZeros => MirOperationKind::CountLeadingZeros {
            value,
            ty: ty.clone(),
        },
        LirOperationUnary::CountTrailingZeros => MirOperationKind::CountTrailingZeros {
            value,
            ty: ty.clone(),
        },
        _ => MirOperationKind::Intrinsic {
            name: format!("lir.unary.{op:?}").to_lowercase(),
            arguments: vec![value],
            result_types: vec![ty.clone()],
        },
    };

    block.append_operation(MirOperation::new(Some(result.clone()), kind));
    MirValue::named(result, ty)
}

fn lower_binary_expression(
    op: LirOperationBinary,
    left: &LirExpression,
    right: &LirExpression,
    bits: u16,
    block: &mut MirBlock,
    context: &mut LoweringContext,
) -> MirValue {
    let lhs = lower_expression(left, block, context);
    let rhs = lower_expression(right, block, context);
    let ty = match op {
        LirOperationBinary::FAdd
        | LirOperationBinary::FSub
        | LirOperationBinary::FMul
        | LirOperationBinary::FDiv => MirType::float(bits.max(1)),
        _ => mir_type_for_bits(bits),
    };
    let result = context.next_name("bin");

    let kind = match op {
        LirOperationBinary::Add => MirOperationKind::Add {
            lhs,
            rhs,
            ty: ty.clone(),
        },
        LirOperationBinary::Sub => MirOperationKind::Sub {
            lhs,
            rhs,
            ty: ty.clone(),
        },
        LirOperationBinary::Mul => MirOperationKind::Mul {
            lhs,
            rhs,
            ty: ty.clone(),
        },
        LirOperationBinary::FAdd => MirOperationKind::FAdd {
            lhs,
            rhs,
            ty: ty.clone(),
        },
        LirOperationBinary::FSub => MirOperationKind::FSub {
            lhs,
            rhs,
            ty: ty.clone(),
        },
        LirOperationBinary::FMul => MirOperationKind::FMul {
            lhs,
            rhs,
            ty: ty.clone(),
        },
        LirOperationBinary::FDiv => MirOperationKind::FDiv {
            lhs,
            rhs,
            ty: ty.clone(),
        },
        LirOperationBinary::And => MirOperationKind::And {
            lhs,
            rhs,
            ty: ty.clone(),
        },
        LirOperationBinary::Or => MirOperationKind::Or {
            lhs,
            rhs,
            ty: ty.clone(),
        },
        LirOperationBinary::Xor => MirOperationKind::Xor {
            lhs,
            rhs,
            ty: ty.clone(),
        },
        LirOperationBinary::Shl => MirOperationKind::Shl {
            lhs,
            rhs,
            ty: ty.clone(),
        },
        LirOperationBinary::LShr => MirOperationKind::LShr {
            lhs,
            rhs,
            ty: ty.clone(),
        },
        LirOperationBinary::AShr => MirOperationKind::AShr {
            lhs,
            rhs,
            ty: ty.clone(),
        },
        LirOperationBinary::UDiv => MirOperationKind::UDiv {
            lhs,
            rhs,
            ty: ty.clone(),
        },
        LirOperationBinary::SDiv => MirOperationKind::SDiv {
            lhs,
            rhs,
            ty: ty.clone(),
        },
        LirOperationBinary::URem => MirOperationKind::URem {
            lhs,
            rhs,
            ty: ty.clone(),
        },
        LirOperationBinary::SRem => MirOperationKind::SRem {
            lhs,
            rhs,
            ty: ty.clone(),
        },
        LirOperationBinary::RotateLeft => MirOperationKind::RotateLeft {
            lhs,
            rhs,
            ty: ty.clone(),
        },
        LirOperationBinary::RotateRight => MirOperationKind::RotateRight {
            lhs,
            rhs,
            ty: ty.clone(),
        },
        _ => MirOperationKind::Intrinsic {
            name: format!("lir.binary.{op:?}").to_lowercase(),
            arguments: vec![lhs, rhs],
            result_types: vec![ty.clone()],
        },
    };

    block.append_operation(MirOperation::new(Some(result.clone()), kind));
    MirValue::named(result, ty)
}

fn lower_cast_expression(
    op: LirOperationCast,
    arg: &LirExpression,
    bits: u16,
    block: &mut MirBlock,
    context: &mut LoweringContext,
) -> MirValue {
    let value = lower_expression(arg, block, context);
    let ty = match op {
        LirOperationCast::IntToFloat
        | LirOperationCast::UIntToFloat
        | LirOperationCast::FloatExtend
        | LirOperationCast::FloatTruncate => MirType::float(bits.max(1)),
        _ => mir_type_for_bits(bits),
    };
    let result = context.next_name("cast");

    let kind = match op {
        LirOperationCast::ZeroExtend => MirOperationKind::Cast {
            op: MirCastOperation::ZeroExtend,
            value,
            ty: ty.clone(),
        },
        LirOperationCast::SignExtend => MirOperationKind::Cast {
            op: MirCastOperation::SignExtend,
            value,
            ty: ty.clone(),
        },
        LirOperationCast::Truncate => MirOperationKind::Cast {
            op: MirCastOperation::Truncate,
            value,
            ty: ty.clone(),
        },
        LirOperationCast::Bitcast => MirOperationKind::Cast {
            op: MirCastOperation::Bitcast,
            value,
            ty: ty.clone(),
        },
        LirOperationCast::IntToFloat => MirOperationKind::Cast {
            op: MirCastOperation::IntToFloat,
            value,
            ty: ty.clone(),
        },
        LirOperationCast::UIntToFloat => MirOperationKind::Cast {
            op: MirCastOperation::UIntToFloat,
            value,
            ty: ty.clone(),
        },
        LirOperationCast::FloatToInt => MirOperationKind::Cast {
            op: MirCastOperation::FloatToInt,
            value,
            ty: ty.clone(),
        },
        LirOperationCast::FloatToUInt => MirOperationKind::Cast {
            op: MirCastOperation::FloatToUInt,
            value,
            ty: ty.clone(),
        },
        LirOperationCast::FloatExtend => MirOperationKind::Cast {
            op: MirCastOperation::FloatExtend,
            value,
            ty: ty.clone(),
        },
        LirOperationCast::FloatTruncate => MirOperationKind::Cast {
            op: MirCastOperation::FloatTruncate,
            value,
            ty: ty.clone(),
        },
    };

    block.append_operation(MirOperation::new(Some(result.clone()), kind));
    MirValue::named(result, ty)
}

fn lower_compare_expression(
    op: LirOperationCompare,
    left: &LirExpression,
    right: &LirExpression,
    bits: u16,
    block: &mut MirBlock,
    context: &mut LoweringContext,
) -> MirValue {
    let lhs = lower_expression(left, block, context);
    let rhs = lower_expression(right, block, context);
    let result_ty = MirType::integer(1);
    let result = context.next_name("cmp");
    let operand_ty = match op {
        LirOperationCompare::Ordered
        | LirOperationCompare::Unordered
        | LirOperationCompare::Oeq
        | LirOperationCompare::One
        | LirOperationCompare::Olt
        | LirOperationCompare::Ole
        | LirOperationCompare::Ogt
        | LirOperationCompare::Oge
        | LirOperationCompare::Ueq
        | LirOperationCompare::Une
        | LirOperationCompare::UltFp
        | LirOperationCompare::UleFp
        | LirOperationCompare::UgtFp
        | LirOperationCompare::UgeFp => MirType::float(bits.max(1)),
        _ => mir_type_for_bits(bits),
    };

    let kind = match op {
        LirOperationCompare::Eq => MirOperationKind::Icmp {
            op: MirCompareOperation::Eq,
            lhs,
            rhs,
            ty: operand_ty.clone(),
        },
        LirOperationCompare::Ne => MirOperationKind::Icmp {
            op: MirCompareOperation::Ne,
            lhs,
            rhs,
            ty: operand_ty.clone(),
        },
        LirOperationCompare::Ult => MirOperationKind::Icmp {
            op: MirCompareOperation::Ult,
            lhs,
            rhs,
            ty: operand_ty.clone(),
        },
        LirOperationCompare::Ule => MirOperationKind::Icmp {
            op: MirCompareOperation::Ule,
            lhs,
            rhs,
            ty: operand_ty.clone(),
        },
        LirOperationCompare::Ugt => MirOperationKind::Icmp {
            op: MirCompareOperation::Ugt,
            lhs,
            rhs,
            ty: operand_ty.clone(),
        },
        LirOperationCompare::Uge => MirOperationKind::Icmp {
            op: MirCompareOperation::Uge,
            lhs,
            rhs,
            ty: operand_ty.clone(),
        },
        LirOperationCompare::Slt => MirOperationKind::Icmp {
            op: MirCompareOperation::Slt,
            lhs,
            rhs,
            ty: operand_ty.clone(),
        },
        LirOperationCompare::Sle => MirOperationKind::Icmp {
            op: MirCompareOperation::Sle,
            lhs,
            rhs,
            ty: operand_ty.clone(),
        },
        LirOperationCompare::Sgt => MirOperationKind::Icmp {
            op: MirCompareOperation::Sgt,
            lhs,
            rhs,
            ty: operand_ty.clone(),
        },
        LirOperationCompare::Sge => MirOperationKind::Icmp {
            op: MirCompareOperation::Sge,
            lhs,
            rhs,
            ty: operand_ty.clone(),
        },
        LirOperationCompare::Ordered => MirOperationKind::Fcmp {
            op: MirFloatCompareOperation::Ordered,
            lhs,
            rhs,
            ty: operand_ty.clone(),
        },
        LirOperationCompare::Unordered => MirOperationKind::Fcmp {
            op: MirFloatCompareOperation::Unordered,
            lhs,
            rhs,
            ty: operand_ty.clone(),
        },
        LirOperationCompare::Oeq => MirOperationKind::Fcmp {
            op: MirFloatCompareOperation::Oeq,
            lhs,
            rhs,
            ty: operand_ty.clone(),
        },
        LirOperationCompare::One => MirOperationKind::Fcmp {
            op: MirFloatCompareOperation::One,
            lhs,
            rhs,
            ty: operand_ty.clone(),
        },
        LirOperationCompare::Olt => MirOperationKind::Fcmp {
            op: MirFloatCompareOperation::Olt,
            lhs,
            rhs,
            ty: operand_ty.clone(),
        },
        LirOperationCompare::Ole => MirOperationKind::Fcmp {
            op: MirFloatCompareOperation::Ole,
            lhs,
            rhs,
            ty: operand_ty.clone(),
        },
        LirOperationCompare::Ogt => MirOperationKind::Fcmp {
            op: MirFloatCompareOperation::Ogt,
            lhs,
            rhs,
            ty: operand_ty.clone(),
        },
        LirOperationCompare::Oge => MirOperationKind::Fcmp {
            op: MirFloatCompareOperation::Oge,
            lhs,
            rhs,
            ty: operand_ty.clone(),
        },
        LirOperationCompare::Ueq => MirOperationKind::Fcmp {
            op: MirFloatCompareOperation::Ueq,
            lhs,
            rhs,
            ty: operand_ty.clone(),
        },
        LirOperationCompare::Une => MirOperationKind::Fcmp {
            op: MirFloatCompareOperation::Une,
            lhs,
            rhs,
            ty: operand_ty.clone(),
        },
        LirOperationCompare::UltFp => MirOperationKind::Fcmp {
            op: MirFloatCompareOperation::Ult,
            lhs,
            rhs,
            ty: operand_ty.clone(),
        },
        LirOperationCompare::UleFp => MirOperationKind::Fcmp {
            op: MirFloatCompareOperation::Ule,
            lhs,
            rhs,
            ty: operand_ty.clone(),
        },
        LirOperationCompare::UgtFp => MirOperationKind::Fcmp {
            op: MirFloatCompareOperation::Ugt,
            lhs,
            rhs,
            ty: operand_ty.clone(),
        },
        LirOperationCompare::UgeFp => MirOperationKind::Fcmp {
            op: MirFloatCompareOperation::Uge,
            lhs,
            rhs,
            ty: operand_ty,
        },
    };

    block.append_operation(MirOperation::new(Some(result.clone()), kind));
    MirValue::named(result, result_ty)
}

fn expression_arguments(expression: &LirExpression) -> Vec<&LirExpression> {
    match expression {
        LirExpression::Select {
            condition,
            when_true,
            when_false,
            ..
        } => vec![condition, when_true, when_false],
        LirExpression::Extract { arg, .. } => vec![arg],
        LirExpression::Concat { parts, .. } => parts.iter().collect(),
        LirExpression::Intrinsic { args, .. } => args.iter().collect(),
        LirExpression::Allocate { .. } => Vec::new(),
        LirExpression::ReadProperty { reference, .. } => vec![reference],
        LirExpression::ReadElement {
            reference, index, ..
        } => vec![reference, index],
        _ => Vec::new(),
    }
}

fn resolve_block_target(
    target: &LirExpression,
    address_to_block: &HashMap<u64, String>,
    block: &mut MirBlock,
    context: &mut LoweringContext,
) -> MirControlTarget {
    match target {
        LirExpression::Const { value, .. } => u64::try_from(*value)
            .ok()
            .and_then(|address| {
                address_to_block
                    .get(&address)
                    .cloned()
                    .map(MirControlTarget::direct)
            })
            .unwrap_or_else(|| MirControlTarget::direct(format!("block_{value:x}"))),
        LirExpression::Function { name, .. } | LirExpression::DataAddress { name, .. } => {
            MirControlTarget::direct(name.clone())
        }
        _ => MirControlTarget::block_indirect(lower_expression(target, block, context)),
    }
}

fn resolve_call_target(
    target: &LirExpression,
    block: &mut MirBlock,
    context: &mut LoweringContext,
) -> MirControlTarget {
    match target {
        LirExpression::Const { value, .. } => {
            MirControlTarget::direct(format!("function_{value:x}"))
        }
        LirExpression::Function { name, .. } | LirExpression::DataAddress { name, .. } => {
            MirControlTarget::direct(name.clone())
        }
        _ => MirControlTarget::function_indirect(lower_expression(target, block, context)),
    }
}

fn lower_address_space(space: &LirAddressSpace) -> MirAddressSpace {
    match space {
        LirAddressSpace::Default => MirAddressSpace::default_space(),
        LirAddressSpace::Stack => MirAddressSpace::stack(),
        LirAddressSpace::Heap => MirAddressSpace::heap(),
        LirAddressSpace::Global => MirAddressSpace::global(),
        LirAddressSpace::Io => MirAddressSpace::io(),
        LirAddressSpace::State => MirAddressSpace::named("state".to_string()),
        LirAddressSpace::CpuMemory { name }
        | LirAddressSpace::Segment { name }
        | LirAddressSpace::Named { name } => MirAddressSpace::named(name.clone()),
    }
}

fn call_result_binding(
    semantic: &Lir,
    context: &mut LoweringContext,
) -> (Option<String>, Vec<MirType>, Option<(LirLocation, MirType)>) {
    let Some(location) = call_return_location(semantic) else {
        return (None, Vec::new(), None);
    };
    let ty = mir_type_for_bits(location.bits());
    let result = context.next_name("call");
    (Some(result.clone()), vec![ty.clone()], Some((location, ty)))
}

fn call_return_location(semantic: &Lir) -> Option<LirLocation> {
    if let Some(abi) = semantic.abi.as_ref() {
        if let Some(location) = abi
            .return_locations
            .iter()
            .find(|location| matches!(location, LirLocation::Register { .. }))
        {
            return Some(location.clone());
        }
    }

    match semantic
        .encoding
        .as_ref()
        .map(|encoding| encoding.architecture.as_str())
    {
        Some("amd64") => Some(LirLocation::Register {
            name: "rax".to_string(),
            bits: 64,
        }),
        Some("i386") => Some(LirLocation::Register {
            name: "eax".to_string(),
            bits: 32,
        }),
        Some("arm64") => Some(LirLocation::Register {
            name: "x0".to_string(),
            bits: 64,
        }),
        _ => None,
    }
}

fn call_argument_values(
    semantic: &Lir,
    function_abi: Option<&LirAbi>,
    block: &mut MirBlock,
    context: &mut LoweringContext,
) -> Vec<MirValue> {
    let owned_abi;
    let abi = if let Some(abi) = semantic.abi.as_ref() {
        abi
    } else {
        owned_abi = infer_call_abi(semantic, function_abi, block);
        let abi = owned_abi.as_ref().or(function_abi);
        let Some(abi) = abi else {
            return Vec::new();
        };
        abi
    };

    abi.function_arguments
        .iter()
        .map(|location| lower_call_argument_location(location, abi, block, context))
        .collect()
}

fn lower_call_argument_location(
    location: &LirLocation,
    call_abi: &LirAbi,
    block: &mut MirBlock,
    context: &mut LoweringContext,
) -> MirValue {
    match location {
        LirLocation::Register { .. }
        | LirLocation::Flag { .. }
        | LirLocation::ProgramCounter { .. }
        | LirLocation::Temporary { .. } => MirValue::named(
            context.location_name_with_abi(location, Some(call_abi)),
            mir_type_for_bits(location.bits()),
        ),
        LirLocation::StackMemory { name, offset, bits } => {
            let ty = mir_type_for_bits(*bits);
            let result = context.next_name("arg");
            block.append_operation(MirOperation::new(
                Some(result.clone()),
                MirOperationKind::Load {
                    address_space: MirAddressSpace::named(name.clone()),
                    address: MirValue::integer(*offset as i128, 64),
                    ty: ty.clone(),
                },
            ));
            MirValue::named(result, ty)
        }
        LirLocation::Memory { space, addr, bits } => {
            let ty = mir_type_for_bits(*bits);
            let result = context.next_name("arg");
            let address = lower_expression(addr, block, context);
            block.append_operation(MirOperation::new(
                Some(result.clone()),
                MirOperationKind::Load {
                    address_space: lower_address_space(space),
                    address,
                    ty: ty.clone(),
                },
            ));
            MirValue::named(result, ty)
        }
        LirLocation::IndexedMemory { name, index, bits } => {
            let ty = mir_type_for_bits(*bits);
            let result = context.next_name("arg");
            let address = lower_expression(index, block, context);
            block.append_operation(MirOperation::new(
                Some(result.clone()),
                MirOperationKind::Load {
                    address_space: MirAddressSpace::named(name.clone()),
                    address,
                    ty: ty.clone(),
                },
            ));
            MirValue::named(result, ty)
        }
    }
}

fn infer_call_abi(
    semantic: &Lir,
    function_abi: Option<&LirAbi>,
    block: &MirBlock,
) -> Option<LirAbi> {
    let architecture = semantic
        .encoding
        .as_ref()
        .map(|encoding| encoding.architecture.as_str())?;

    match architecture {
        "amd64" => infer_amd64_call_abi(function_abi, block),
        "i386" => infer_i386_call_abi(function_abi, block),
        "arm64" => LirCpu::arm64().ok().and_then(|cpu| LirAbi::sysv(&cpu).ok()),
        _ => None,
    }
}

fn infer_amd64_call_abi(function_abi: Option<&LirAbi>, block: &MirBlock) -> Option<LirAbi> {
    let cpu = LirCpu::amd64().ok()?;
    let windows = LirAbi::windows64(&cpu).ok()?;
    let sysv = LirAbi::sysv(&cpu).ok()?;

    let windows_score = score_call_abi_candidates(block, function_abi, &windows);
    let sysv_score = score_call_abi_candidates(block, function_abi, &sysv);

    if windows_score >= sysv_score {
        Some(windows)
    } else {
        Some(sysv)
    }
}

fn infer_i386_call_abi(function_abi: Option<&LirAbi>, block: &MirBlock) -> Option<LirAbi> {
    let cpu = LirCpu::i386().ok()?;
    let fastcall = LirAbi::fastcall(&cpu).ok()?;
    if score_call_abi_candidates(block, function_abi, &fastcall) > 0 {
        return Some(fastcall);
    }
    LirAbi::cdecl(&cpu).ok()
}

fn score_call_abi_candidates(
    block: &MirBlock,
    function_abi: Option<&LirAbi>,
    abi: &LirAbi,
) -> usize {
    let mut defined = HashSet::new();
    for operation in &block.operations {
        if let Some(result) = operation.result.as_ref() {
            defined.insert(result.as_str());
        }
    }

    abi.function_arguments
        .iter()
        .filter_map(|location| match location {
            LirLocation::Register { name, .. } => {
                Some(canonical_register_role(name, function_abi).unwrap_or(name.clone()))
            }
            _ => None,
        })
        .filter(|name| defined.contains(name.as_str()))
        .count()
}

fn mir_type_for_expression(expression: &LirExpression) -> MirType {
    match expression {
        LirExpression::Const { bits, .. }
        | LirExpression::Function { bits, .. }
        | LirExpression::DataAddress { bits, .. }
        | LirExpression::AddressOf { bits, .. }
        | LirExpression::Load { bits, .. }
        | LirExpression::Unary { bits, .. }
        | LirExpression::Binary { bits, .. }
        | LirExpression::Cast { bits, .. }
        | LirExpression::Compare { bits, .. }
        | LirExpression::Select { bits, .. }
        | LirExpression::Extract { bits, .. }
        | LirExpression::Concat { bits, .. }
        | LirExpression::Undefined { bits }
        | LirExpression::Poison { bits }
        | LirExpression::Intrinsic { bits, .. }
        | LirExpression::Null { bits }
        | LirExpression::Allocate { bits, .. }
        | LirExpression::ReadProperty { bits, .. }
        | LirExpression::ReadElement { bits, .. } => mir_type_for_bits(*bits),
        LirExpression::Read(location) => mir_type_for_bits(location.bits()),
    }
}

fn mir_type_for_bits(bits: u16) -> MirType {
    MirType::integer(bits.max(1))
}

fn default_function_abi(lir: &LirFunction) -> Option<LirAbi> {
    let architecture = lir
        .instructions()
        .into_iter()
        .find_map(|instruction| instruction.encoding.as_ref())
        .map(|encoding| encoding.architecture.as_str())?;

    match architecture {
        "amd64" => default_amd64_function_abi(lir),
        "i386" => LirCpu::i386().ok().and_then(|cpu| LirAbi::cdecl(&cpu).ok()),
        "arm64" => LirCpu::arm64().ok().and_then(|cpu| LirAbi::sysv(&cpu).ok()),
        _ => None,
    }
}

fn default_amd64_function_abi(lir: &LirFunction) -> Option<LirAbi> {
    let cpu = LirCpu::amd64().ok()?;
    if lir_references_windows_symbols(lir) {
        LirAbi::windows64(&cpu).ok()
    } else {
        LirAbi::sysv(&cpu).ok()
    }
}

fn lir_references_windows_symbols(lir: &LirFunction) -> bool {
    lir.name.as_deref().is_some_and(is_windows_symbol_name)
        || lir.blocks.iter().any(|block| {
            block.instructions.iter().any(|instruction| {
                instruction
                    .effects
                    .iter()
                    .any(effect_references_windows_symbols)
                    || terminator_references_windows_symbols(&instruction.terminator)
            })
        })
}

fn is_windows_symbol_name(name: &str) -> bool {
    name.to_ascii_lowercase().contains(".dll!")
}

fn effect_references_windows_symbols(effect: &LirEffect) -> bool {
    match effect {
        LirEffect::Set { expression, .. } | LirEffect::Push { expression, .. } => {
            expression_references_windows_symbols(expression)
        }
        LirEffect::Store {
            addr, expression, ..
        } => {
            expression_references_windows_symbols(addr)
                || expression_references_windows_symbols(expression)
        }
        LirEffect::MemorySet {
            addr, value, count, ..
        } => {
            expression_references_windows_symbols(addr)
                || expression_references_windows_symbols(value)
                || expression_references_windows_symbols(count)
        }
        LirEffect::MemoryCopy {
            src_addr,
            dst_addr,
            count,
            decrement,
            ..
        } => {
            expression_references_windows_symbols(src_addr)
                || expression_references_windows_symbols(dst_addr)
                || expression_references_windows_symbols(count)
                || expression_references_windows_symbols(decrement)
        }
        LirEffect::AtomicCmpXchg {
            addr,
            expected,
            desired,
            ..
        } => {
            expression_references_windows_symbols(addr)
                || expression_references_windows_symbols(expected)
                || expression_references_windows_symbols(desired)
        }
        LirEffect::WriteProperty {
            reference,
            expression,
            ..
        } => {
            expression_references_windows_symbols(reference)
                || expression_references_windows_symbols(expression)
        }
        LirEffect::WriteElement {
            reference,
            index,
            expression,
            ..
        } => {
            expression_references_windows_symbols(reference)
                || expression_references_windows_symbols(index)
                || expression_references_windows_symbols(expression)
        }
        LirEffect::Intrinsic { args, .. } => args.iter().any(expression_references_windows_symbols),
        LirEffect::Pop { .. }
        | LirEffect::Fence { .. }
        | LirEffect::Trap { .. }
        | LirEffect::Nop => false,
    }
}

fn terminator_references_windows_symbols(terminator: &LirTerminator) -> bool {
    match terminator {
        LirTerminator::FallThrough | LirTerminator::Unreachable | LirTerminator::Trap => false,
        LirTerminator::Jump { target } => expression_references_windows_symbols(target),
        LirTerminator::Branch {
            condition,
            true_target,
            false_target,
        } => {
            expression_references_windows_symbols(condition)
                || expression_references_windows_symbols(true_target)
                || expression_references_windows_symbols(false_target)
        }
        LirTerminator::Call {
            target,
            return_target,
            ..
        } => {
            expression_references_windows_symbols(target)
                || return_target
                    .as_ref()
                    .is_some_and(expression_references_windows_symbols)
        }
        LirTerminator::Return { expression } => expression
            .as_ref()
            .is_some_and(expression_references_windows_symbols),
    }
}

fn expression_references_windows_symbols(expression: &LirExpression) -> bool {
    match expression {
        LirExpression::Function { name, .. } | LirExpression::DataAddress { name, .. } => {
            is_windows_symbol_name(name)
        }
        LirExpression::Load { addr, .. }
        | LirExpression::Unary { arg: addr, .. }
        | LirExpression::Cast { arg: addr, .. }
        | LirExpression::Extract { arg: addr, .. }
        | LirExpression::ReadProperty {
            reference: addr, ..
        } => expression_references_windows_symbols(addr),
        LirExpression::Binary { left, right, .. } | LirExpression::Compare { left, right, .. } => {
            expression_references_windows_symbols(left)
                || expression_references_windows_symbols(right)
        }
        LirExpression::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            expression_references_windows_symbols(condition)
                || expression_references_windows_symbols(when_true)
                || expression_references_windows_symbols(when_false)
        }
        LirExpression::Concat { parts, .. } => {
            parts.iter().any(expression_references_windows_symbols)
        }
        LirExpression::Intrinsic { args, .. } => {
            args.iter().any(expression_references_windows_symbols)
        }
        LirExpression::ReadElement {
            reference, index, ..
        } => {
            expression_references_windows_symbols(reference)
                || expression_references_windows_symbols(index)
        }
        LirExpression::Const { .. }
        | LirExpression::AddressOf { .. }
        | LirExpression::Read(_)
        | LirExpression::Undefined { .. }
        | LirExpression::Poison { .. }
        | LirExpression::Null { .. }
        | LirExpression::Allocate { .. } => false,
    }
}

fn append_entry_parameters(block: &mut MirBlock, parameters: &[MirBlockParameter]) {
    for parameter in parameters {
        let exists = block
            .parameters
            .iter()
            .any(|existing| existing == parameter);
        if !exists {
            block.append_parameter(parameter.clone());
        }
    }
}

fn build_entry_parameters(
    lir: &LirFunction,
    abi: Option<&LirAbi>,
    explicit_abi: bool,
    context: &mut LoweringContext,
) -> Vec<MirBlockParameter> {
    let Some(abi) = abi else {
        return Vec::new();
    };

    let locations = if explicit_abi {
        abi.function_arguments.clone()
    } else {
        detect_entry_parameter_locations(lir, abi)
    };

    locations
        .iter()
        .filter_map(|location| lower_entry_parameter(location, context))
        .collect()
}

fn lower_entry_parameter(
    location: &LirLocation,
    context: &mut LoweringContext,
) -> Option<MirBlockParameter> {
    match location {
        LirLocation::Register { .. }
        | LirLocation::Flag { .. }
        | LirLocation::ProgramCounter { .. }
        | LirLocation::Temporary { .. } => Some(MirBlockParameter::new(
            Some(context.location_name(location)),
            mir_type_for_bits(location.bits()),
        )),
        LirLocation::StackMemory { name, bits, .. }
        | LirLocation::IndexedMemory { name, bits, .. } => Some(MirBlockParameter::new(
            Some(name.clone()),
            mir_type_for_bits(*bits),
        )),
        LirLocation::Memory { .. } => None,
    }
}

fn detect_entry_parameter_locations(lir: &LirFunction, abi: &LirAbi) -> Vec<LirLocation> {
    let mut defined = std::collections::BTreeSet::<String>::new();
    let mut used = std::collections::BTreeSet::<String>::new();
    let candidates = abi
        .function_arguments
        .iter()
        .map(|location| (candidate_location_key(location, &abi.cpu), location.clone()))
        .collect::<Vec<_>>();

    for block in &lir.blocks {
        for instruction in &block.instructions {
            for effect in &instruction.effects {
                collect_effect_reads(effect, &abi.cpu, &candidates, &defined, &mut used);
                collect_effect_defs(effect, &abi.cpu, &mut defined);
            }
            collect_terminator_reads(
                &instruction.terminator,
                &abi.cpu,
                &candidates,
                &defined,
                &mut used,
            );
        }
    }

    candidates
        .into_iter()
        .filter_map(|(key, location)| used.contains(&key).then_some(location))
        .collect()
}

fn collect_effect_reads(
    effect: &LirEffect,
    cpu: &LirCpu,
    candidates: &[(String, LirLocation)],
    defined: &std::collections::BTreeSet<String>,
    used: &mut std::collections::BTreeSet<String>,
) {
    match effect {
        LirEffect::Set { expression, .. } => {
            collect_expression_reads(expression, cpu, candidates, defined, used)
        }
        LirEffect::Store {
            addr, expression, ..
        } => {
            collect_expression_reads(addr, cpu, candidates, defined, used);
            collect_expression_reads(expression, cpu, candidates, defined, used);
        }
        LirEffect::MemoryCopy {
            src_addr,
            dst_addr,
            count,
            decrement,
            ..
        } => {
            collect_expression_reads(src_addr, cpu, candidates, defined, used);
            collect_expression_reads(dst_addr, cpu, candidates, defined, used);
            collect_expression_reads(count, cpu, candidates, defined, used);
            collect_expression_reads(decrement, cpu, candidates, defined, used);
        }
        LirEffect::Push { expression, .. } => {
            collect_expression_reads(expression, cpu, candidates, defined, used);
        }
        LirEffect::Intrinsic { args, .. } => {
            for arg in args {
                collect_expression_reads(arg, cpu, candidates, defined, used);
            }
        }
        LirEffect::Pop { .. }
        | LirEffect::Trap { .. }
        | LirEffect::Fence { .. }
        | LirEffect::Nop
        | LirEffect::MemorySet { .. }
        | LirEffect::AtomicCmpXchg { .. }
        | LirEffect::WriteProperty { .. }
        | LirEffect::WriteElement { .. } => {}
    }
}

fn collect_effect_defs(
    effect: &LirEffect,
    cpu: &LirCpu,
    defined: &mut std::collections::BTreeSet<String>,
) {
    match effect {
        LirEffect::Set { dst, .. } | LirEffect::Pop { dst, .. } => {
            defined.insert(candidate_location_key(dst, cpu));
        }
        LirEffect::Intrinsic { outputs, .. } => {
            for output in outputs {
                defined.insert(candidate_location_key(output, cpu));
            }
        }
        _ => {}
    }
}

fn collect_terminator_reads(
    terminator: &LirTerminator,
    cpu: &LirCpu,
    candidates: &[(String, LirLocation)],
    defined: &std::collections::BTreeSet<String>,
    used: &mut std::collections::BTreeSet<String>,
) {
    match terminator {
        LirTerminator::Jump { target } => {
            collect_expression_reads(target, cpu, candidates, defined, used)
        }
        LirTerminator::Branch {
            condition,
            true_target,
            false_target,
        } => {
            collect_expression_reads(condition, cpu, candidates, defined, used);
            collect_expression_reads(true_target, cpu, candidates, defined, used);
            collect_expression_reads(false_target, cpu, candidates, defined, used);
        }
        LirTerminator::Call {
            target,
            return_target,
            ..
        } => {
            collect_expression_reads(target, cpu, candidates, defined, used);
            if let Some(return_target) = return_target {
                collect_expression_reads(return_target, cpu, candidates, defined, used);
            }
        }
        LirTerminator::Return { expression } => {
            if let Some(expression) = expression {
                collect_expression_reads(expression, cpu, candidates, defined, used);
            }
        }
        LirTerminator::FallThrough | LirTerminator::Unreachable | LirTerminator::Trap => {}
    }
}

fn collect_expression_reads(
    expression: &LirExpression,
    cpu: &LirCpu,
    candidates: &[(String, LirLocation)],
    defined: &std::collections::BTreeSet<String>,
    used: &mut std::collections::BTreeSet<String>,
) {
    match expression {
        LirExpression::Read(location) => {
            let key = candidate_location_key(location, cpu);
            if !defined.contains(&key) && candidates.iter().any(|(candidate, _)| candidate == &key)
            {
                used.insert(key);
            }
        }
        LirExpression::AddressOf { location, .. } => {
            let key = candidate_location_key(location, cpu);
            if !defined.contains(&key) && candidates.iter().any(|(candidate, _)| candidate == &key)
            {
                used.insert(key);
            }
        }
        LirExpression::Load { addr, .. }
        | LirExpression::Cast { arg: addr, .. }
        | LirExpression::Unary { arg: addr, .. }
        | LirExpression::Extract { arg: addr, .. }
        | LirExpression::ReadProperty {
            reference: addr, ..
        } => collect_expression_reads(addr, cpu, candidates, defined, used),
        LirExpression::Binary { left, right, .. } | LirExpression::Compare { left, right, .. } => {
            collect_expression_reads(left, cpu, candidates, defined, used);
            collect_expression_reads(right, cpu, candidates, defined, used);
        }
        LirExpression::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            collect_expression_reads(condition, cpu, candidates, defined, used);
            collect_expression_reads(when_true, cpu, candidates, defined, used);
            collect_expression_reads(when_false, cpu, candidates, defined, used);
        }
        LirExpression::Concat { parts, .. } | LirExpression::Intrinsic { args: parts, .. } => {
            for part in parts {
                collect_expression_reads(part, cpu, candidates, defined, used);
            }
        }
        LirExpression::ReadElement {
            reference, index, ..
        } => {
            collect_expression_reads(reference, cpu, candidates, defined, used);
            collect_expression_reads(index, cpu, candidates, defined, used);
        }
        LirExpression::Const { .. }
        | LirExpression::Function { .. }
        | LirExpression::DataAddress { .. }
        | LirExpression::Undefined { .. }
        | LirExpression::Poison { .. }
        | LirExpression::Null { .. }
        | LirExpression::Allocate { .. } => {}
    }
}

fn candidate_location_key(location: &LirLocation, cpu: &LirCpu) -> String {
    match location {
        LirLocation::Register { name, .. } => cpu
            .resolve_register(name)
            .map(|resolution| format!("reg:{}", resolution.storage_name))
            .unwrap_or_else(|| format!("reg:{name}")),
        LirLocation::Flag { name, .. } => format!("flag:{name}"),
        LirLocation::ProgramCounter { .. } => "pc".to_string(),
        LirLocation::Temporary { id, .. } => format!("tmp:{id}"),
        LirLocation::Memory { space, bits, .. } => format!("mem:{space:?}:{bits}"),
        LirLocation::IndexedMemory { name, bits, .. } => format!("indexed:{name}:{bits}"),
        LirLocation::StackMemory { name, bits, offset } => format!("stack:{name}:{offset}:{bits}"),
    }
}

fn canonical_register_role(raw_name: &str, abi: Option<&LirAbi>) -> Option<String> {
    if matches!(raw_name, "rip" | "eip" | "pc") {
        return Some("pc".to_string());
    }
    if matches!(raw_name, "rsp" | "esp" | "sp" | "sp_el0" | "sp_el1") {
        return Some("sp".to_string());
    }
    if matches!(raw_name, "rbp" | "ebp" | "bp" | "fp" | "x29" | "w29") {
        return Some("fp".to_string());
    }
    if let Some(abi) = abi {
        for (index, location) in abi.function_arguments.iter().enumerate() {
            if matches_register_role_location(location, raw_name, &abi.cpu) {
                return Some(format!("arg{index}"));
            }
        }
        for (index, location) in abi.return_locations.iter().enumerate() {
            if matches_register_role_location(location, raw_name, &abi.cpu) {
                return Some(format!("ret{index}"));
            }
        }
    }
    None
}

fn canonical_flag_name(raw_name: &str) -> Option<String> {
    match raw_name {
        "zf" | "z" => Some("zero".to_string()),
        "cf" | "c" => Some("carry".to_string()),
        "of" | "v" => Some("overflow".to_string()),
        "sf" | "n" => Some("sign".to_string()),
        "pf" => Some("parity".to_string()),
        "af" => Some("adjust".to_string()),
        _ => None,
    }
}

fn matches_register_role_location(location: &LirLocation, raw_name: &str, cpu: &LirCpu) -> bool {
    let LirLocation::Register { name, .. } = location else {
        return false;
    };
    match (
        canonical_register_storage_name(cpu, name),
        canonical_register_storage_name(cpu, raw_name),
    ) {
        (Some(expected), Some(actual)) => expected == actual,
        _ => name == raw_name,
    }
}

fn canonical_register_storage_name(cpu: &LirCpu, name: &str) -> Option<String> {
    cpu.resolve_register(name)
        .map(|resolution| resolution.storage_name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::lir::{LirBlock, LirEncoding, LirInstruction, LirStatus};

    fn amd64_instruction_with_terminator(terminator: LirTerminator) -> LirInstruction {
        LirInstruction {
            version: 1,
            status: LirStatus::Complete,
            abi: None,
            encoding: Some(LirEncoding {
                architecture: "amd64".to_string(),
                mnemonic: "call".to_string(),
                disassembly: String::new(),
                address: 0x1000,
                bytes: Vec::new(),
            }),
            temporaries: Vec::new(),
            effects: Vec::new(),
            terminator,
            diagnostics: Vec::new(),
        }
    }

    #[test]
    fn defaults_amd64_pe_import_references_to_windows64_abi() {
        let lir = LirFunction {
            name: Some("function_1000".to_string()),
            abi: None,
            blocks: vec![LirBlock {
                name: Some("entry".to_string()),
                instructions: vec![amd64_instruction_with_terminator(LirTerminator::Call {
                    target: LirExpression::Function {
                        name: "ntdll.dll!RtlFreeHeap".to_string(),
                        bits: 64,
                    },
                    return_target: None,
                    does_return: Some(true),
                })],
            }],
        };

        let abi = default_function_abi(&lir).expect("expected inferred ABI");
        assert_eq!(abi.name, "windows64");
    }

    #[test]
    fn defaults_amd64_without_pe_import_references_to_sysv_abi() {
        let lir = LirFunction {
            name: Some("function_1000".to_string()),
            abi: None,
            blocks: vec![LirBlock {
                name: Some("entry".to_string()),
                instructions: vec![amd64_instruction_with_terminator(LirTerminator::Return {
                    expression: None,
                })],
            }],
        };

        let abi = default_function_abi(&lir).expect("expected inferred ABI");
        assert_eq!(abi.name, "sysv");
    }

    #[test]
    fn lowers_amd64_zero_extending_alias_write_to_parent_width() {
        let cpu = LirCpu::amd64().expect("amd64 cpu");
        let lir = LirFunction {
            name: Some("function_1000".to_string()),
            abi: Some(LirAbi::windows64(&cpu).expect("windows64 abi")),
            blocks: vec![LirBlock {
                name: Some("entry".to_string()),
                instructions: vec![LirInstruction {
                    effects: vec![LirEffect::Set {
                        dst: LirLocation::Register {
                            name: "esi".to_string(),
                            bits: 32,
                        },
                        expression: LirExpression::Binary {
                            op: LirOperationBinary::Xor,
                            left: Box::new(LirExpression::Read(Box::new(LirLocation::Register {
                                name: "esi".to_string(),
                                bits: 32,
                            }))),
                            right: Box::new(LirExpression::Read(Box::new(LirLocation::Register {
                                name: "esi".to_string(),
                                bits: 32,
                            }))),
                            bits: 32,
                        },
                    }],
                    ..amd64_instruction_with_terminator(LirTerminator::Return { expression: None })
                }],
            }],
        };

        let mir = lower_lir_to_mir(None, &lir).expect("lowered mir");
        let operations = &mir.blocks()[0].operations;
        assert!(matches!(
            operations[1].kind,
            MirOperationKind::Cast {
                op: MirCastOperation::ZeroExtend,
                ty: MirType::Integer(64),
                ..
            }
        ));
        assert!(matches!(
            operations[2].kind,
            MirOperationKind::Copy {
                ty: MirType::Integer(64),
                ..
            }
        ));
    }
}
