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

use super::block::{MirBlock, MirBlockParameter};
use super::kind::{MirCastOperation, MirCompareOperation, MirFloatCompareOperation, MirType};
use super::memory::MirAddressSpace;
use super::mir::{MirFunction, MirModule};
use super::operation::{MirOperation, MirOperationKind};
use super::target::MirControlTarget;
use super::terminator::MirTerminator;
use super::value::MirValue;

pub fn format_mir_function(mir: &MirFunction) -> String {
    let context = crate::ir::mlir::context();
    mir_function_operation(&context, mir)
        .and_then(|op| op.to_string())
        .unwrap_or_else(|error| format!("// mlir print failed: {error}"))
}

pub fn format_mir_module(module: &MirModule) -> String {
    let context = crate::ir::mlir::context();
    mir_module_operation(&context, module)
        .and_then(|op| crate::ir::mlir::MlirDocument::from_context_and_ops(context, vec![op]))
        .and_then(|document| document.text())
        .unwrap_or_else(|error| format!("// mlir print failed: {error}"))
}

fn mir_operation_operation(
    context: &mlir::Context,
    operation: &MirOperation,
) -> mlir::Result<mlir::Operation> {
    let (name, mut attrs) = mir_operation_attrs(context, operation);
    if let Some(result) = &operation.result {
        attrs.push(crate::ir::mlir::string_attr(context, "result", result));
    }
    crate::ir::mlir::operation(context, name, attrs, Vec::new())
}

fn mir_terminator_operation(
    context: &mlir::Context,
    terminator: &MirTerminator,
) -> mlir::Result<mlir::Operation> {
    let (name, attrs) = mir_terminator_attrs(context, terminator);
    crate::ir::mlir::operation(context, name, attrs, Vec::new())
}

fn mir_operation_attrs(
    context: &mlir::Context,
    operation: &MirOperation,
) -> (&'static str, Vec<mlir::NamedAttribute>) {
    match &operation.kind {
        MirOperationKind::Copy { value, ty } => (
            "binlex.mir.copy",
            attrs(
                context,
                &[("value", format_value(value)), ("ty", format_type(ty))],
            ),
        ),
        MirOperationKind::Add { lhs, rhs, ty } => {
            binary_attrs(context, "binlex.mir.add", lhs, rhs, ty)
        }
        MirOperationKind::Sub { lhs, rhs, ty } => {
            binary_attrs(context, "binlex.mir.sub", lhs, rhs, ty)
        }
        MirOperationKind::Mul { lhs, rhs, ty } => {
            binary_attrs(context, "binlex.mir.mul", lhs, rhs, ty)
        }
        MirOperationKind::FAdd { lhs, rhs, ty } => {
            binary_attrs(context, "binlex.mir.fadd", lhs, rhs, ty)
        }
        MirOperationKind::FSub { lhs, rhs, ty } => {
            binary_attrs(context, "binlex.mir.fsub", lhs, rhs, ty)
        }
        MirOperationKind::FMul { lhs, rhs, ty } => {
            binary_attrs(context, "binlex.mir.fmul", lhs, rhs, ty)
        }
        MirOperationKind::FDiv { lhs, rhs, ty } => {
            binary_attrs(context, "binlex.mir.fdiv", lhs, rhs, ty)
        }
        MirOperationKind::And { lhs, rhs, ty } => {
            binary_attrs(context, "binlex.mir.and", lhs, rhs, ty)
        }
        MirOperationKind::Or { lhs, rhs, ty } => {
            binary_attrs(context, "binlex.mir.or", lhs, rhs, ty)
        }
        MirOperationKind::Xor { lhs, rhs, ty } => {
            binary_attrs(context, "binlex.mir.xor", lhs, rhs, ty)
        }
        MirOperationKind::Shl { lhs, rhs, ty } => {
            binary_attrs(context, "binlex.mir.shl", lhs, rhs, ty)
        }
        MirOperationKind::LShr { lhs, rhs, ty } => {
            binary_attrs(context, "binlex.mir.lshr", lhs, rhs, ty)
        }
        MirOperationKind::AShr { lhs, rhs, ty } => {
            binary_attrs(context, "binlex.mir.ashr", lhs, rhs, ty)
        }
        MirOperationKind::UDiv { lhs, rhs, ty } => {
            binary_attrs(context, "binlex.mir.udiv", lhs, rhs, ty)
        }
        MirOperationKind::SDiv { lhs, rhs, ty } => {
            binary_attrs(context, "binlex.mir.sdiv", lhs, rhs, ty)
        }
        MirOperationKind::URem { lhs, rhs, ty } => {
            binary_attrs(context, "binlex.mir.urem", lhs, rhs, ty)
        }
        MirOperationKind::SRem { lhs, rhs, ty } => {
            binary_attrs(context, "binlex.mir.srem", lhs, rhs, ty)
        }
        MirOperationKind::RotateLeft { lhs, rhs, ty } => {
            binary_attrs(context, "binlex.mir.rol", lhs, rhs, ty)
        }
        MirOperationKind::RotateRight { lhs, rhs, ty } => {
            binary_attrs(context, "binlex.mir.ror", lhs, rhs, ty)
        }
        MirOperationKind::Select {
            condition,
            when_true,
            when_false,
            ty,
        } => (
            "binlex.mir.select",
            attrs(
                context,
                &[
                    ("condition", format_value(condition)),
                    ("true", format_value(when_true)),
                    ("false", format_value(when_false)),
                    ("ty", format_type(ty)),
                ],
            ),
        ),
        MirOperationKind::Concat { parts, ty } => (
            "binlex.mir.concat",
            attrs(
                context,
                &[
                    (
                        "parts",
                        parts
                            .iter()
                            .map(format_value)
                            .collect::<Vec<_>>()
                            .join("\n"),
                    ),
                    ("ty", format_type(ty)),
                ],
            ),
        ),
        MirOperationKind::Extract { value, lsb, ty } => (
            "binlex.mir.extract",
            attrs(
                context,
                &[
                    ("value", format_value(value)),
                    ("lsb", lsb.to_string()),
                    ("ty", format_type(ty)),
                ],
            ),
        ),
        MirOperationKind::Not { value, ty } => unary_attrs(context, "binlex.mir.not", value, ty),
        MirOperationKind::Neg { value, ty } => unary_attrs(context, "binlex.mir.neg", value, ty),
        MirOperationKind::Popcount { value, ty } => {
            unary_attrs(context, "binlex.mir.popcount", value, ty)
        }
        MirOperationKind::CountLeadingZeros { value, ty } => {
            unary_attrs(context, "binlex.mir.ctlz", value, ty)
        }
        MirOperationKind::CountTrailingZeros { value, ty } => {
            unary_attrs(context, "binlex.mir.cttz", value, ty)
        }
        MirOperationKind::Load {
            address_space,
            address,
            ty,
        } => (
            "binlex.mir.load",
            attrs(
                context,
                &[
                    ("space", format_address_space(address_space)),
                    ("address", format_value(address)),
                    ("ty", format_type(ty)),
                ],
            ),
        ),
        MirOperationKind::AddressOf {
            address_space,
            address,
            pointee_ty,
            ty,
        } => (
            "binlex.mir.address_of",
            attrs(
                context,
                &[
                    ("space", format_address_space(address_space)),
                    ("address", format_value(address)),
                    ("pointee_ty", format_type(pointee_ty)),
                    ("ty", format_type(ty)),
                ],
            ),
        ),
        MirOperationKind::Store {
            address_space,
            address,
            value,
            ty,
        } => (
            "binlex.mir.store",
            attrs(
                context,
                &[
                    ("space", format_address_space(address_space)),
                    ("address", format_value(address)),
                    ("value", format_value(value)),
                    ("ty", format_type(ty)),
                ],
            ),
        ),
        MirOperationKind::MemoryCopy {
            src_space,
            src_address,
            dst_space,
            dst_address,
            count,
            element_bits,
            decrement,
        } => (
            "binlex.mir.memcpy",
            attrs(
                context,
                &[
                    ("src_space", format_address_space(src_space)),
                    ("src_address", format_value(src_address)),
                    ("dst_space", format_address_space(dst_space)),
                    ("dst_address", format_value(dst_address)),
                    ("count", format_value(count)),
                    ("element_bits", element_bits.to_string()),
                    ("decrement", format_value(decrement)),
                ],
            ),
        ),
        MirOperationKind::Icmp { op, lhs, rhs, ty } => {
            let mut attrs = attrs(context, &[("op", format_compare(op).to_string())]);
            attrs.extend(binary_attr_values(context, lhs, rhs, ty));
            ("binlex.mir.icmp", attrs)
        }
        MirOperationKind::Fcmp { op, lhs, rhs, ty } => {
            let mut attrs = attrs(context, &[("op", format_float_compare(op).to_string())]);
            attrs.extend(binary_attr_values(context, lhs, rhs, ty));
            ("binlex.mir.fcmp", attrs)
        }
        MirOperationKind::Cast { op, value, ty } => (
            "binlex.mir.cast",
            attrs(
                context,
                &[
                    ("op", format_cast(op).to_string()),
                    ("value", format_value(value)),
                    ("ty", format_type(ty)),
                ],
            ),
        ),
        MirOperationKind::Call {
            target,
            abi,
            arguments,
            result_types,
            clobbers,
            memory_effects,
        } => {
            let mut values = vec![
                ("target", format_control_target(target)),
                (
                    "arguments",
                    arguments
                        .iter()
                        .map(format_value)
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                (
                    "result_types",
                    result_types
                        .iter()
                        .map(format_type)
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                (
                    "clobbers",
                    clobbers
                        .iter()
                        .map(|clobber| {
                            format!("%{}: {}", clobber.register, format_type(&clobber.ty))
                        })
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                (
                    "memory_effects",
                    memory_effects
                        .iter()
                        .map(format_address_space)
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
            ];
            if let Some(abi) = abi {
                values.push(("abi", abi.name.clone()));
            }
            ("binlex.mir.call", attrs(context, &values))
        }
        MirOperationKind::Intrinsic {
            name,
            arguments,
            result_types,
        } => (
            "binlex.mir.intrinsic",
            attrs(
                context,
                &[
                    ("name", name.clone()),
                    (
                        "arguments",
                        arguments
                            .iter()
                            .map(format_value)
                            .collect::<Vec<_>>()
                            .join("\n"),
                    ),
                    (
                        "result_types",
                        result_types
                            .iter()
                            .map(format_type)
                            .collect::<Vec<_>>()
                            .join("\n"),
                    ),
                ],
            ),
        ),
    }
}

fn mir_terminator_attrs(
    context: &mlir::Context,
    terminator: &MirTerminator,
) -> (&'static str, Vec<mlir::NamedAttribute>) {
    match terminator {
        MirTerminator::Jump { target, arguments } => (
            "binlex.mir.jump",
            attrs(
                context,
                &[
                    ("target", format_control_target(target)),
                    (
                        "arguments",
                        arguments
                            .iter()
                            .map(format_value)
                            .collect::<Vec<_>>()
                            .join("\n"),
                    ),
                ],
            ),
        ),
        MirTerminator::CondBr {
            condition,
            then_target,
            then_arguments,
            else_target,
            else_arguments,
        } => (
            "binlex.mir.cond_br",
            attrs(
                context,
                &[
                    ("condition", format_value(condition)),
                    ("then_target", format_control_target(then_target)),
                    (
                        "then_arguments",
                        then_arguments
                            .iter()
                            .map(format_value)
                            .collect::<Vec<_>>()
                            .join("\n"),
                    ),
                    ("else_target", format_control_target(else_target)),
                    (
                        "else_arguments",
                        else_arguments
                            .iter()
                            .map(format_value)
                            .collect::<Vec<_>>()
                            .join("\n"),
                    ),
                ],
            ),
        ),
        MirTerminator::Return { values } => (
            "binlex.mir.return",
            attrs(
                context,
                &[(
                    "values",
                    values
                        .iter()
                        .map(format_value)
                        .collect::<Vec<_>>()
                        .join("\n"),
                )],
            ),
        ),
        MirTerminator::Trap => ("binlex.mir.trap", Vec::new()),
        MirTerminator::Unreachable => ("binlex.mir.unreachable", Vec::new()),
    }
}

fn unary_attrs(
    context: &mlir::Context,
    name: &'static str,
    value: &MirValue,
    ty: &MirType,
) -> (&'static str, Vec<mlir::NamedAttribute>) {
    (
        name,
        attrs(
            context,
            &[("value", format_value(value)), ("ty", format_type(ty))],
        ),
    )
}

fn binary_attrs(
    context: &mlir::Context,
    name: &'static str,
    lhs: &MirValue,
    rhs: &MirValue,
    ty: &MirType,
) -> (&'static str, Vec<mlir::NamedAttribute>) {
    (name, binary_attr_values(context, lhs, rhs, ty))
}

fn binary_attr_values(
    context: &mlir::Context,
    lhs: &MirValue,
    rhs: &MirValue,
    ty: &MirType,
) -> Vec<mlir::NamedAttribute> {
    attrs(
        context,
        &[
            ("lhs", format_value(lhs)),
            ("rhs", format_value(rhs)),
            ("ty", format_type(ty)),
        ],
    )
}

fn attrs(context: &mlir::Context, values: &[(&str, String)]) -> Vec<mlir::NamedAttribute> {
    values
        .iter()
        .map(|(name, value)| crate::ir::mlir::string_attr(context, name, value))
        .collect()
}

fn mir_block_operation(context: &mlir::Context, block: &MirBlock) -> mlir::Result<mlir::Operation> {
    let mut attrs = vec![crate::ir::mlir::string_attr(
        context,
        "sym_name",
        &block.name,
    )];
    if !block.parameters.is_empty() {
        attrs.push(crate::ir::mlir::string_attr(
            context,
            "parameters",
            &block
                .parameters
                .iter()
                .map(format_block_parameter)
                .collect::<Vec<_>>()
                .join("\n"),
        ));
    }
    let mut ops = block
        .operations
        .iter()
        .map(|operation| mir_operation_operation(context, operation))
        .collect::<mlir::Result<Vec<_>>>()?;
    if let Some(terminator) = &block.terminator {
        ops.push(mir_terminator_operation(context, terminator)?);
    }
    crate::ir::mlir::operation(
        context,
        "binlex.mir.block",
        attrs,
        vec![crate::ir::mlir::region_with_ops(ops)],
    )
}

fn mir_function_operation(
    context: &mlir::Context,
    function: &MirFunction,
) -> mlir::Result<mlir::Operation> {
    let name = function
        .name
        .clone()
        .unwrap_or_else(|| "anonymous".to_string());
    let ops = function
        .blocks
        .iter()
        .map(|block| mir_block_operation(context, block))
        .collect::<mlir::Result<Vec<_>>>()?;
    crate::ir::mlir::operation(
        context,
        "binlex.mir.function",
        vec![crate::ir::mlir::string_attr(context, "sym_name", &name)],
        vec![crate::ir::mlir::region_with_ops(ops)],
    )
}

pub(crate) fn mir_module_operation(
    context: &mlir::Context,
    module: &MirModule,
) -> mlir::Result<mlir::Operation> {
    let name = module
        .name
        .clone()
        .unwrap_or_else(|| "anonymous".to_string());
    let ops = module
        .functions
        .iter()
        .map(|function| mir_function_operation(context, function))
        .collect::<mlir::Result<Vec<_>>>()?;
    crate::ir::mlir::operation(
        context,
        "binlex.mir.module",
        vec![crate::ir::mlir::string_attr(context, "sym_name", &name)],
        vec![crate::ir::mlir::region_with_ops(ops)],
    )
}

fn format_block_parameter(parameter: &MirBlockParameter) -> String {
    let name = parameter.name.clone().unwrap_or_else(|| "_".to_string());
    format!("%{}: {}", name, format_type(&parameter.ty))
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
                MirType::Pointer { .. }
                | MirType::TypeDefinition { .. }
                | MirType::Structure { .. }
                | MirType::Union { .. } => {
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
                    returns
                        .iter()
                        .map(format_type)
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            format!("fn({parameters})->{returns}")
        }
        MirType::Memory => "mem".to_string(),
        MirType::TypeDefinition { name }
        | MirType::Structure { name, .. }
        | MirType::Union { name, .. } => name.clone(),
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
