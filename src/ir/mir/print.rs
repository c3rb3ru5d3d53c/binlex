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

use super::block::MirBlockParameter;
use super::kind::{MirCastOperation, MirCompareOperation, MirFloatCompareOperation, MirType};
use super::memory::MirAddressSpace;
use super::mir::{MirFunction, MirModule};
use super::operation::{MirCallClobber, MirOperation, MirOperationKind};
use super::target::MirControlTarget;
use super::terminator::MirTerminator;
use super::value::MirValue;

pub fn format_mir_function(mir: &MirFunction) -> String {
    let mut lines = Vec::new();
    let name = mir.name.clone().unwrap_or_else(|| "anonymous".to_string());
    lines.push(format!("mir.function {} {{", format_code_location(&name)));
    for block in &mir.blocks {
        let params = block
            .parameters
            .iter()
            .map(format_block_parameter)
            .collect::<Vec<_>>()
            .join(", ");
        if params.is_empty() {
            lines.push(format!("  {}:", format_code_location(&block.name)));
        } else {
            lines.push(format!(
                "  {}({}):",
                format_code_location(&block.name),
                params
            ));
        }
        for operation in &block.operations {
            lines.push(format!("    {}", format_operation(operation)));
        }
        if let Some(terminator) = &block.terminator {
            lines.push(format!("    {}", format_terminator(terminator)));
        }
    }
    lines.push("}".to_string());
    lines.join("\n")
}

pub fn format_mir_module(module: &MirModule) -> String {
    let name = module
        .name
        .clone()
        .unwrap_or_else(|| "anonymous".to_string());
    let mut lines = vec![format!("mir.module {} {{", format_code_location(&name))];

    for (index, function) in module.functions.iter().enumerate() {
        if index > 0 {
            lines.push(String::new());
        }
        for line in format_mir_function(function).lines() {
            lines.push(format!("  {line}"));
        }
    }

    lines.push("}".to_string());
    lines.join("\n")
}

fn format_block_parameter(parameter: &MirBlockParameter) -> String {
    let name = parameter.name.clone().unwrap_or_else(|| "_".to_string());
    format!("%{}: {}", name, format_type(&parameter.ty))
}

fn format_operation(operation: &MirOperation) -> String {
    let prefix = operation
        .result
        .as_ref()
        .map(|result| format!("%{} = ", result))
        .unwrap_or_default();
    let body = match &operation.kind {
        MirOperationKind::Copy { value, ty } => {
            format!("mir.copy {} : {}", format_value(value), format_type(ty))
        }
        MirOperationKind::Add { lhs, rhs, ty } => {
            format!(
                "mir.add {}, {} : {}",
                format_value(lhs),
                format_value(rhs),
                format_type(ty)
            )
        }
        MirOperationKind::Sub { lhs, rhs, ty } => {
            format!(
                "mir.sub {}, {} : {}",
                format_value(lhs),
                format_value(rhs),
                format_type(ty)
            )
        }
        MirOperationKind::Mul { lhs, rhs, ty } => {
            format!(
                "mir.mul {}, {} : {}",
                format_value(lhs),
                format_value(rhs),
                format_type(ty)
            )
        }
        MirOperationKind::FAdd { lhs, rhs, ty } => {
            format!(
                "mir.fadd {}, {} : {}",
                format_value(lhs),
                format_value(rhs),
                format_type(ty)
            )
        }
        MirOperationKind::FSub { lhs, rhs, ty } => {
            format!(
                "mir.fsub {}, {} : {}",
                format_value(lhs),
                format_value(rhs),
                format_type(ty)
            )
        }
        MirOperationKind::FMul { lhs, rhs, ty } => {
            format!(
                "mir.fmul {}, {} : {}",
                format_value(lhs),
                format_value(rhs),
                format_type(ty)
            )
        }
        MirOperationKind::FDiv { lhs, rhs, ty } => {
            format!(
                "mir.fdiv {}, {} : {}",
                format_value(lhs),
                format_value(rhs),
                format_type(ty)
            )
        }
        MirOperationKind::And { lhs, rhs, ty } => {
            format!(
                "mir.and {}, {} : {}",
                format_value(lhs),
                format_value(rhs),
                format_type(ty)
            )
        }
        MirOperationKind::Or { lhs, rhs, ty } => {
            format!(
                "mir.or {}, {} : {}",
                format_value(lhs),
                format_value(rhs),
                format_type(ty)
            )
        }
        MirOperationKind::Xor { lhs, rhs, ty } => {
            format!(
                "mir.xor {}, {} : {}",
                format_value(lhs),
                format_value(rhs),
                format_type(ty)
            )
        }
        MirOperationKind::Shl { lhs, rhs, ty } => {
            format!(
                "mir.shl {}, {} : {}",
                format_value(lhs),
                format_value(rhs),
                format_type(ty)
            )
        }
        MirOperationKind::LShr { lhs, rhs, ty } => {
            format!(
                "mir.lshr {}, {} : {}",
                format_value(lhs),
                format_value(rhs),
                format_type(ty)
            )
        }
        MirOperationKind::AShr { lhs, rhs, ty } => {
            format!(
                "mir.ashr {}, {} : {}",
                format_value(lhs),
                format_value(rhs),
                format_type(ty)
            )
        }
        MirOperationKind::UDiv { lhs, rhs, ty } => {
            format!(
                "mir.udiv {}, {} : {}",
                format_value(lhs),
                format_value(rhs),
                format_type(ty)
            )
        }
        MirOperationKind::SDiv { lhs, rhs, ty } => {
            format!(
                "mir.sdiv {}, {} : {}",
                format_value(lhs),
                format_value(rhs),
                format_type(ty)
            )
        }
        MirOperationKind::URem { lhs, rhs, ty } => {
            format!(
                "mir.urem {}, {} : {}",
                format_value(lhs),
                format_value(rhs),
                format_type(ty)
            )
        }
        MirOperationKind::SRem { lhs, rhs, ty } => {
            format!(
                "mir.srem {}, {} : {}",
                format_value(lhs),
                format_value(rhs),
                format_type(ty)
            )
        }
        MirOperationKind::RotateLeft { lhs, rhs, ty } => {
            format!(
                "mir.rol {}, {} : {}",
                format_value(lhs),
                format_value(rhs),
                format_type(ty)
            )
        }
        MirOperationKind::RotateRight { lhs, rhs, ty } => {
            format!(
                "mir.ror {}, {} : {}",
                format_value(lhs),
                format_value(rhs),
                format_type(ty)
            )
        }
        MirOperationKind::Select {
            condition,
            when_true,
            when_false,
            ty,
        } => format!(
            "mir.select {}, {}, {} : {}",
            format_value(condition),
            format_value(when_true),
            format_value(when_false),
            format_type(ty)
        ),
        MirOperationKind::Concat { parts, ty } => format!(
            "mir.concat ({}) : {}",
            parts
                .iter()
                .map(format_value)
                .collect::<Vec<_>>()
                .join(", "),
            format_type(ty)
        ),
        MirOperationKind::Extract { value, lsb, ty } => format!(
            "mir.extract {}, lsb {}, bits {} : {}",
            format_value(value),
            lsb,
            type_bits(ty),
            format_type(ty)
        ),
        MirOperationKind::Not { value, ty } => {
            format!("mir.not {} : {}", format_value(value), format_type(ty))
        }
        MirOperationKind::Neg { value, ty } => {
            format!("mir.neg {} : {}", format_value(value), format_type(ty))
        }
        MirOperationKind::Popcount { value, ty } => {
            format!("mir.popcount {} : {}", format_value(value), format_type(ty))
        }
        MirOperationKind::CountLeadingZeros { value, ty } => {
            format!("mir.clz {} : {}", format_value(value), format_type(ty))
        }
        MirOperationKind::CountTrailingZeros { value, ty } => {
            format!("mir.ctz {} : {}", format_value(value), format_type(ty))
        }
        MirOperationKind::Load {
            address_space,
            address,
            ty,
        } => format!(
            "mir.load {}, {} : {}",
            format_address_space(address_space),
            format_value(address),
            format_type(ty)
        ),
        MirOperationKind::Store {
            address_space,
            address,
            value,
            ty,
        } => format!(
            "mir.store {}, {}, {} : {}",
            format_address_space(address_space),
            format_value(address),
            format_value(value),
            format_type(ty)
        ),
        MirOperationKind::MemoryCopy {
            src_space,
            src_address,
            dst_space,
            dst_address,
            count,
            element_bits,
            decrement,
        } => format!(
            "mir.memcpy {}:{}, {}:{}, count {}, element_bits {}, decrement {}",
            format_address_space(src_space),
            format_value(src_address),
            format_address_space(dst_space),
            format_value(dst_address),
            format_value(count),
            element_bits,
            format_value(decrement)
        ),
        MirOperationKind::Icmp { op, lhs, rhs, ty } => format!(
            "mir.icmp {} {}, {} : {}",
            format_compare(op),
            format_value(lhs),
            format_value(rhs),
            format_type(ty)
        ),
        MirOperationKind::Fcmp { op, lhs, rhs, ty } => format!(
            "mir.fcmp {} {}, {} : {}",
            format_float_compare(op),
            format_value(lhs),
            format_value(rhs),
            format_type(ty)
        ),
        MirOperationKind::Cast { op, value, ty } => format!(
            "mir.cast {} {} : {}",
            format_cast(op),
            format_value(value),
            format_type(ty)
        ),
        MirOperationKind::Call {
            target,
            arguments,
            result_types,
            clobbers,
            memory_effects,
        } => format!(
            "mir.call {}({}) -> ({}){}{}",
            format_control_target(target),
            arguments
                .iter()
                .map(format_value)
                .collect::<Vec<_>>()
                .join(", "),
            result_types
                .iter()
                .map(format_type)
                .collect::<Vec<_>>()
                .join(", "),
            format_call_clobbers(clobbers),
            format_call_memory_effects(memory_effects)
        ),
        MirOperationKind::Intrinsic {
            name,
            arguments,
            result_types,
        } => format!(
            "mir.intrinsic {}({}) -> ({})",
            name,
            arguments
                .iter()
                .map(format_value)
                .collect::<Vec<_>>()
                .join(", "),
            result_types
                .iter()
                .map(format_type)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    };
    format!("{prefix}{body}")
}

fn format_terminator(terminator: &MirTerminator) -> String {
    match terminator {
        MirTerminator::Jump { target, arguments } => format!(
            "mir.jump {}({})",
            format_control_target(target),
            arguments
                .iter()
                .map(format_value)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        MirTerminator::CondBr {
            condition,
            then_target,
            then_arguments,
            else_target,
            else_arguments,
        } => format!(
            "mir.cond_br {}, {}({}), {}({})",
            format_value(condition),
            format_control_target(then_target),
            then_arguments
                .iter()
                .map(format_value)
                .collect::<Vec<_>>()
                .join(", "),
            format_control_target(else_target),
            else_arguments
                .iter()
                .map(format_value)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        MirTerminator::Return { values } => format!(
            "mir.return {}",
            values
                .iter()
                .map(format_value)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        MirTerminator::Trap => "mir.trap".to_string(),
        MirTerminator::Unreachable => "mir.unreachable".to_string(),
    }
}

fn format_value(value: &MirValue) -> String {
    match value {
        MirValue::Named { name, .. } => format_named_value(name),
        MirValue::Integer { value, bits } => format!("{value}:i{bits}"),
        MirValue::Boolean(value) => value.to_string(),
        MirValue::Null { ty } => format!("null:{}", format_type(ty)),
        MirValue::Undef { ty } => format!("undef:{}", format_type(ty)),
    }
}

fn format_typed_value(value: &MirValue) -> String {
    match value {
        MirValue::Named { name, ty } => {
            let rendered = format_named_value(name);
            match ty {
                MirType::Pointer { .. } | MirType::Custom { .. } => {
                    format!("{rendered}:{}", format_type(ty))
                }
                _ => rendered,
            }
        }
        _ => format_value(value),
    }
}

fn format_named_value(name: &str) -> String {
    if let Some(pointer) = format_pointer_name(name) {
        return pointer;
    }
    format!("%{}", name)
}

fn format_code_location(name: &str) -> String {
    if name.starts_with('@') {
        name.to_string()
    } else {
        format!("@{}", name)
    }
}

fn format_control_target(target: &MirControlTarget) -> String {
    match target {
        MirControlTarget::Direct(name) => format_code_location(name),
        MirControlTarget::FunctionIndirect(value) => {
            format!("function_indirect {}", format_typed_value(value))
        }
        MirControlTarget::BlockIndirect(value) => {
            format!("block_indirect {}", format_typed_value(value))
        }
    }
}

fn format_pointer_name(name: &str) -> Option<String> {
    let rest = name.strip_prefix("ptr.")?;
    let (kind, value) = rest.split_once('.')?;
    let rendered = match kind {
        "local" => format!("&local[{value}]"),
        "argument" => format!("&argument[{value}]"),
        "spill" => format!("&spill[{value}]"),
        "incoming" => format!("&incoming[{value}]"),
        "saved_frame" => format!("&saved_frame[{value}]"),
        "return_address" => format!("&return_address[{value}]"),
        "stack" => "&stack".to_string(),
        "heap" => format!("&heap[{value}]"),
        "global" => format!("&global[{value}]"),
        "io" => "&io".to_string(),
        "default" => "&default".to_string(),
        "named" => format!("&{value}"),
        _ => return None,
    };
    Some(rendered)
}

fn format_type(ty: &MirType) -> String {
    match ty {
        MirType::Void => "void".to_string(),
        MirType::Integer(bits) => format!("i{bits}"),
        MirType::Float(bits) => format!("f{bits}"),
        MirType::Pointer { pointee } => format!("ptr<{}>", format_type(pointee)),
        MirType::Function {
            parameters,
            returns,
        } => {
            let parameters = parameters
                .iter()
                .map(format_type)
                .collect::<Vec<_>>()
                .join(", ");
            let returns = if returns.is_empty() {
                "void".to_string()
            } else if returns.len() == 1 {
                format_type(&returns[0])
            } else {
                format!(
                    "({})",
                    returns.iter().map(format_type).collect::<Vec<_>>().join(", ")
                )
            };
            format!("fn({parameters})->{returns}")
        }
        MirType::Memory => "mem".to_string(),
        MirType::Custom { name } => name.clone(),
    }
}

fn type_bits(ty: &MirType) -> u16 {
    match ty {
        MirType::Integer(bits) | MirType::Float(bits) => *bits,
        _ => 0,
    }
}

fn format_address_space(address_space: &MirAddressSpace) -> String {
    match address_space {
        MirAddressSpace::Default => "default".to_string(),
        MirAddressSpace::Stack => "stack".to_string(),
        MirAddressSpace::Heap => "heap".to_string(),
        MirAddressSpace::Global => "global".to_string(),
        MirAddressSpace::HeapObject { name } => format!("heap[{name}]"),
        MirAddressSpace::GlobalObject { name } => format!("global[{name}]"),
        MirAddressSpace::Io => "io".to_string(),
        MirAddressSpace::Local { name } => format!("local[{name}]"),
        MirAddressSpace::Argument { name } => format!("argument[{name}]"),
        MirAddressSpace::Spill { name } => format!("spill[{name}]"),
        MirAddressSpace::Incoming { name } => format!("incoming[{name}]"),
        MirAddressSpace::SavedFrame { name } => format!("saved_frame[{name}]"),
        MirAddressSpace::ReturnAddress { name } => format!("return_address[{name}]"),
        MirAddressSpace::Named { name } => name.clone(),
    }
}

fn format_call_clobbers(clobbers: &[MirCallClobber]) -> String {
    if clobbers.is_empty() {
        return String::new();
    }

    format!(
        " clobbers [{}]",
        clobbers
            .iter()
            .map(|clobber| format!("%{}: {}", clobber.register, format_type(&clobber.ty)))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn format_call_memory_effects(memory_effects: &[MirAddressSpace]) -> String {
    if memory_effects.is_empty() {
        return String::new();
    }

    format!(
        " effects [{}]",
        memory_effects
            .iter()
            .map(format_address_space)
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn format_compare(op: &MirCompareOperation) -> &'static str {
    match op {
        MirCompareOperation::Eq => "eq",
        MirCompareOperation::Ne => "ne",
        MirCompareOperation::Ult => "ult",
        MirCompareOperation::Ule => "ule",
        MirCompareOperation::Ugt => "ugt",
        MirCompareOperation::Uge => "uge",
        MirCompareOperation::Slt => "slt",
        MirCompareOperation::Sle => "sle",
        MirCompareOperation::Sgt => "sgt",
        MirCompareOperation::Sge => "sge",
    }
}

fn format_float_compare(op: &MirFloatCompareOperation) -> &'static str {
    match op {
        MirFloatCompareOperation::Ordered => "ordered",
        MirFloatCompareOperation::Unordered => "unordered",
        MirFloatCompareOperation::Oeq => "oeq",
        MirFloatCompareOperation::One => "one",
        MirFloatCompareOperation::Olt => "olt",
        MirFloatCompareOperation::Ole => "ole",
        MirFloatCompareOperation::Ogt => "ogt",
        MirFloatCompareOperation::Oge => "oge",
        MirFloatCompareOperation::Ueq => "ueq",
        MirFloatCompareOperation::Une => "une",
        MirFloatCompareOperation::Ult => "ult",
        MirFloatCompareOperation::Ule => "ule",
        MirFloatCompareOperation::Ugt => "ugt",
        MirFloatCompareOperation::Uge => "uge",
    }
}

fn format_cast(op: &MirCastOperation) -> &'static str {
    match op {
        MirCastOperation::ZeroExtend => "zext",
        MirCastOperation::SignExtend => "sext",
        MirCastOperation::Truncate => "trunc",
        MirCastOperation::Bitcast => "bitcast",
        MirCastOperation::IntToFloat => "sitofp",
        MirCastOperation::UIntToFloat => "uitofp",
        MirCastOperation::FloatToInt => "fptosi",
        MirCastOperation::FloatToUInt => "fptoui",
        MirCastOperation::FloatExtend => "fpext",
        MirCastOperation::FloatTruncate => "fptrunc",
    }
}
