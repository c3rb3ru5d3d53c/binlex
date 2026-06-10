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

use crate::controlflow::Function;
use crate::irs::mir::{
    MirAddressSpace, MirBlockParameter, MirControlTarget, MirFunction, MirOperation,
    MirOperationKind, MirTerminator, MirType, MirValue,
};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Error;

pub fn lower_function_to_mir(function: &Function<'_>) -> Result<MirFunction, Error> {
    lower_lir_function_to_mir(function, &function.lir()?)
}

pub fn lower_lir_function_to_mir(
    function: &Function<'_>,
    lir: &crate::irs::lir::LirFunction,
) -> Result<MirFunction, Error> {
    lower_lir_function_to_mir_with_symbols(function, lir, &function.cfg.symbols())
}

pub fn lower_lir_function_to_mir_with_symbols(
    function: &Function<'_>,
    lir: &crate::irs::lir::LirFunction,
    symbol_map: &BTreeMap<u64, String>,
) -> Result<MirFunction, Error> {
    let mut mir =
        MirFunction::from_lir(None, lir).map_err(|error| Error::other(error.to_string()))?;
    trim_function_call_arguments_with_symbols(function, &mut mir, symbol_map)?;
    apply_observed_import_signature_with_symbols(function, &mut mir, symbol_map)?;
    apply_observed_call_argument_types(&mut mir);
    Ok(mir)
}

pub(crate) fn trim_function_call_arguments_with_symbols(
    function: &Function<'_>,
    mir: &mut MirFunction,
    symbol_map: &BTreeMap<u64, String>,
) -> Result<(), Error> {
    let entry_parameter_names = mir
        .entry_parameters
        .iter()
        .filter_map(|parameter| parameter.name.clone())
        .collect::<BTreeSet<_>>();
    let defs = build_mir_defs(mir);
    let symbol_to_address = symbol_map
        .iter()
        .map(|(address, name)| (name.clone(), *address))
        .collect::<BTreeMap<_, _>>();

    for block in mir.blocks_mut() {
        for operation in &mut block.operations {
            let MirOperationKind::Call { target, .. } = &mut operation.kind else {
                continue;
            };

            match target {
                MirControlTarget::Direct(target) => {
                    let target_name = target.clone();
                    if import_prototype_arity(&target_name).is_some() {
                        trim_import_or_external_call_arguments(
                            operation,
                            &target_name,
                            &entry_parameter_names,
                            &defs,
                        );
                        continue;
                    }
                    let Some(address) = symbol_to_address.get(target).copied() else {
                        trim_import_or_external_call_arguments(
                            operation,
                            &target_name,
                            &entry_parameter_names,
                            &defs,
                        );
                        continue;
                    };
                    if target.contains('!') {
                        trim_import_or_external_call_arguments(
                            operation,
                            &target_name,
                            &entry_parameter_names,
                            &defs,
                        );
                        continue;
                    }
                    if address == function.address {
                        continue;
                    }
                    if function.cfg.function(address).is_none() {
                        trim_import_or_external_call_arguments(
                            operation,
                            &target_name,
                            &entry_parameter_names,
                            &defs,
                        );
                        continue;
                    }
                }
                MirControlTarget::FunctionIndirect(_) | MirControlTarget::BlockIndirect(_) => {
                    trim_external_call_arguments(operation, &entry_parameter_names, &defs);
                }
            }
        }
    }

    Ok(())
}

fn apply_observed_import_signature_with_symbols(
    function: &Function<'_>,
    mir: &mut MirFunction,
    symbol_map: &BTreeMap<u64, String>,
) -> Result<(), Error> {
    let Some(symbol_name) = symbol_map.get(&function.address) else {
        return Ok(());
    };
    if !symbol_name.contains('!') || !mir.entry_parameters.is_empty() {
        return Ok(());
    }

    let mut observed = Vec::<Option<MirType>>::new();
    let callers = function
        .direct_caller_references()
        .values()
        .copied()
        .collect::<BTreeSet<_>>();

    for caller_address in callers {
        if caller_address == function.address {
            continue;
        }
        let Some(caller) = function.cfg.function(caller_address) else {
            continue;
        };
        let caller_mir = caller.mir()?;
        let defs = build_mir_defs(&caller_mir);
        for block in caller_mir.blocks() {
            for operation in &block.operations {
                let MirOperationKind::Call {
                    target: MirControlTarget::Direct(target),
                    arguments,
                    ..
                } = &operation.kind
                else {
                    continue;
                };
                if target != symbol_name {
                    continue;
                }
                for (index, argument) in arguments.iter().enumerate() {
                    let ty = observed_argument_type(argument, &defs, 0);
                    if observed.len() <= index {
                        observed.resize(index + 1, None);
                    }
                    merge_observed_type(&mut observed[index], ty);
                }
            }
        }
    }

    if observed.is_empty() {
        return Ok(());
    }

    let entry_parameters = observed
        .into_iter()
        .enumerate()
        .filter_map(|(index, ty)| {
            ty.map(|ty| MirBlockParameter::new(Some(format!("arg{index}")), ty))
        })
        .collect::<Vec<_>>();

    if entry_parameters.is_empty() {
        return Ok(());
    }

    mir.entry_parameters = entry_parameters.clone();
    if let Some(entry_block) = mir.blocks_mut().first_mut() {
        entry_block.parameters = entry_parameters;
    }
    Ok(())
}

fn trim_import_or_external_call_arguments(
    operation: &mut MirOperation,
    target: &str,
    entry_parameter_names: &BTreeSet<String>,
    defs: &BTreeMap<String, MirOperationKind>,
) {
    if let Some(arity) = import_prototype_arity(target) {
        trim_local_call_metadata(operation, arity);
    } else {
        trim_external_call_arguments(operation, entry_parameter_names, defs);
    }
}

fn import_prototype_arity(target: &str) -> Option<usize> {
    let name = target
        .rsplit_once('!')
        .map(|(_, symbol)| symbol)
        .unwrap_or(target);
    match name {
        "DeviceIoControl" => Some(8),
        "GetLastError" => Some(0),
        "KernelBaseGetGlobalData" => Some(0),
        "CreateFileA" | "CreateFileW" => Some(7),
        "CloseHandle" | "NtClose" | "RtlSetLastWin32Error" | "SetLastError" => Some(1),
        "NtDeviceIoControlFile" | "ZwDeviceIoControlFile" => Some(10),
        "RtlAllocateHeap" | "RtlFreeHeap" | "RtlMoveMemory" | "RtlCopyMemory" | "memcpy"
        | "memmove" => Some(3),
        _ => None,
    }
}

fn trim_local_call_metadata(operation: &mut MirOperation, keep: usize) {
    let MirOperationKind::Call {
        arguments,
        clobbers,
        memory_effects,
        ..
    } = &mut operation.kind
    else {
        return;
    };

    if keep < arguments.len() {
        arguments.truncate(keep);
    }

    clobbers.retain(
        |clobber| match clobber.register.trim_start_matches('%').strip_prefix("arg") {
            Some(index) => index
                .parse::<usize>()
                .ok()
                .is_some_and(|index| index < keep),
            None => true,
        },
    );

    if keep == 0 {
        memory_effects.retain(
            |effect| !matches!(effect, MirAddressSpace::Incoming { name } if name == "args"),
        );
    }
}

fn trim_external_call_arguments(
    operation: &mut MirOperation,
    entry_parameter_names: &BTreeSet<String>,
    defs: &BTreeMap<String, MirOperationKind>,
) {
    let MirOperationKind::Call {
        arguments,
        clobbers,
        memory_effects,
        ..
    } = &mut operation.kind
    else {
        return;
    };

    let mut filtered_arguments = Vec::with_capacity(arguments.len());
    let mut uses_entry_arguments = false;
    for argument in arguments.iter() {
        if is_meaningful_external_argument(argument, entry_parameter_names, defs) {
            filtered_arguments.push(argument.clone());
        }
        if argument_uses_entry_parameter(argument, entry_parameter_names) {
            uses_entry_arguments = true;
        }
    }

    *arguments = filtered_arguments;
    let keep = arguments.len();
    clobbers.retain(
        |clobber| match clobber.register.trim_start_matches('%').strip_prefix("arg") {
            Some(index) => index
                .parse::<usize>()
                .ok()
                .is_some_and(|index| index < keep),
            None => true,
        },
    );

    if !uses_entry_arguments {
        memory_effects.retain(
            |effect| !matches!(effect, MirAddressSpace::Incoming { name } if name == "args"),
        );
    }
}

fn is_meaningful_external_argument(
    argument: &MirValue,
    entry_parameter_names: &BTreeSet<String>,
    defs: &BTreeMap<String, MirOperationKind>,
) -> bool {
    match argument {
        MirValue::Named { name, .. } => {
            if name.starts_with("arg") && !entry_parameter_names.contains(name) {
                return !name.starts_with("arg_") && defs.contains_key(name);
            }
            true
        }
        MirValue::Undef { .. } => false,
        MirValue::Integer { .. } | MirValue::Boolean(_) | MirValue::Null { .. } => true,
    }
}

fn argument_uses_entry_parameter(
    argument: &MirValue,
    entry_parameter_names: &BTreeSet<String>,
) -> bool {
    match argument {
        MirValue::Named { name, .. } => entry_parameter_names.contains(name),
        _ => false,
    }
}

fn mir_value_type(value: &MirValue) -> MirType {
    match value {
        MirValue::Named { ty, .. } | MirValue::Null { ty } | MirValue::Undef { ty } => ty.clone(),
        MirValue::Integer { bits, .. } => MirType::integer(*bits),
        MirValue::Boolean(_) => MirType::integer(1),
    }
}

fn observed_argument_type(
    value: &MirValue,
    defs: &BTreeMap<String, MirOperationKind>,
    depth: usize,
) -> MirType {
    if depth > 16 {
        return mir_value_type(value);
    }

    if is_pointer_like_value(value, defs, depth) {
        return MirType::pointer(MirType::integer(8));
    }

    match value {
        MirValue::Named { name, ty } => match defs.get(name) {
            Some(MirOperationKind::Copy { value, .. })
            | Some(MirOperationKind::Cast { value, .. }) => {
                observed_argument_type(value, defs, depth + 1)
            }
            _ => ty.clone(),
        },
        _ => mir_value_type(value),
    }
}

fn is_pointer_like_value(
    value: &MirValue,
    defs: &BTreeMap<String, MirOperationKind>,
    depth: usize,
) -> bool {
    if depth > 16 {
        return false;
    }

    match value {
        MirValue::Named { name, ty } => {
            if matches!(ty, MirType::Pointer { .. }) || name.starts_with("ptr.") {
                return true;
            }
            if matches!(name.as_str(), "pc" | "sp" | "fp") {
                return true;
            }
            match defs.get(name) {
                Some(MirOperationKind::Copy { value, .. })
                | Some(MirOperationKind::Cast { value, .. }) => {
                    is_pointer_like_value(value, defs, depth + 1)
                }
                Some(MirOperationKind::Load { address, .. }) => {
                    is_pointer_like_value(address, defs, depth + 1)
                }
                Some(MirOperationKind::Add { lhs, rhs, .. })
                | Some(MirOperationKind::Sub { lhs, rhs, .. }) => {
                    (is_pointer_like_value(lhs, defs, depth + 1)
                        && is_integer_like_value(rhs, defs, depth + 1))
                        || (is_pointer_like_value(rhs, defs, depth + 1)
                            && is_integer_like_value(lhs, defs, depth + 1))
                }
                _ => false,
            }
        }
        MirValue::Null { ty } => matches!(ty, MirType::Pointer { .. }),
        _ => false,
    }
}

fn is_integer_like_value(
    value: &MirValue,
    defs: &BTreeMap<String, MirOperationKind>,
    depth: usize,
) -> bool {
    if depth > 16 {
        return matches!(
            mir_value_type(value),
            MirType::Integer(_)
                | MirType::Float(_)
                | MirType::TypeDefinition { .. }
                | MirType::Structure { .. }
                | MirType::Union { .. }
        );
    }

    match value {
        MirValue::Integer { .. } | MirValue::Boolean(_) => true,
        MirValue::Named { name, ty } => {
            if matches!(
                ty,
                MirType::Integer(_)
                    | MirType::Float(_)
                    | MirType::TypeDefinition { .. }
                    | MirType::Structure { .. }
                    | MirType::Union { .. }
            ) {
                return true;
            }
            match defs.get(name) {
                Some(MirOperationKind::Copy { value, .. })
                | Some(MirOperationKind::Cast { value, .. }) => {
                    is_integer_like_value(value, defs, depth + 1)
                }
                _ => false,
            }
        }
        MirValue::Null { .. } | MirValue::Undef { .. } => false,
    }
}

fn build_mir_defs(mir: &MirFunction) -> BTreeMap<String, MirOperationKind> {
    mir.blocks()
        .iter()
        .flat_map(|block| block.operations.iter())
        .filter_map(|operation| {
            operation
                .result
                .clone()
                .map(|result| (result, operation.kind.clone()))
        })
        .collect()
}

fn apply_observed_call_argument_types(mir: &mut MirFunction) {
    let defs = build_mir_defs(mir);
    let mut updates = BTreeMap::<String, Option<MirType>>::new();

    for block in mir.blocks() {
        for operation in &block.operations {
            let MirOperationKind::Call {
                target,
                arguments,
                result_types,
                ..
            } = &operation.kind
            else {
                continue;
            };
            match target {
                MirControlTarget::Direct(target) => {
                    if !target.contains('!') {
                        continue;
                    }
                }
                MirControlTarget::FunctionIndirect(value)
                | MirControlTarget::BlockIndirect(value) => {
                    if let MirValue::Named { name, .. } = value {
                        let slot = updates.entry(name.clone()).or_insert(None);
                        merge_observed_type(
                            slot,
                            indirect_code_pointer_type(arguments, result_types, &defs),
                        );
                    }
                }
            }
            for argument in arguments {
                let MirValue::Named { name, .. } = argument else {
                    continue;
                };
                let ty = observed_argument_type(argument, &defs, 0);
                if matches!(ty, MirType::Pointer { .. }) {
                    let slot = updates.entry(name.clone()).or_insert(None);
                    merge_observed_type(slot, ty);
                }
            }
        }
    }

    for (name, ty) in updates {
        if let Some(ty) = ty {
            rewrite_named_type(mir, &name, &ty);
        }
    }
}

fn indirect_code_pointer_type(
    arguments: &[MirValue],
    result_types: &[MirType],
    defs: &BTreeMap<String, MirOperationKind>,
) -> MirType {
    let argument_types = arguments
        .iter()
        .map(|argument| observed_argument_type(argument, defs, 0))
        .collect::<Vec<_>>();
    MirType::pointer(MirType::function(argument_types, result_types.to_vec()))
}

fn rewrite_named_type(mir: &mut MirFunction, name: &str, ty: &MirType) {
    for parameter in &mut mir.entry_parameters {
        if parameter.name.as_deref() == Some(name) {
            parameter.ty = ty.clone();
        }
    }
    for block in mir.blocks_mut() {
        for parameter in &mut block.parameters {
            if parameter.name.as_deref() == Some(name) {
                parameter.ty = ty.clone();
            }
        }
        for operation in &mut block.operations {
            if operation.result.as_deref() == Some(name) {
                rewrite_operation_result_type(&mut operation.kind, ty);
            }
            rewrite_value_types_in_operation(&mut operation.kind, name, ty);
        }
        if let Some(terminator) = &mut block.terminator {
            rewrite_value_types_in_terminator(terminator, name, ty);
        }
    }
}

fn rewrite_operation_result_type(kind: &mut MirOperationKind, ty: &MirType) {
    match kind {
        MirOperationKind::Copy { ty: result_ty, .. }
        | MirOperationKind::Add { ty: result_ty, .. }
        | MirOperationKind::Sub { ty: result_ty, .. }
        | MirOperationKind::Mul { ty: result_ty, .. }
        | MirOperationKind::FAdd { ty: result_ty, .. }
        | MirOperationKind::FSub { ty: result_ty, .. }
        | MirOperationKind::FMul { ty: result_ty, .. }
        | MirOperationKind::FDiv { ty: result_ty, .. }
        | MirOperationKind::And { ty: result_ty, .. }
        | MirOperationKind::Or { ty: result_ty, .. }
        | MirOperationKind::Xor { ty: result_ty, .. }
        | MirOperationKind::Shl { ty: result_ty, .. }
        | MirOperationKind::LShr { ty: result_ty, .. }
        | MirOperationKind::AShr { ty: result_ty, .. }
        | MirOperationKind::UDiv { ty: result_ty, .. }
        | MirOperationKind::SDiv { ty: result_ty, .. }
        | MirOperationKind::URem { ty: result_ty, .. }
        | MirOperationKind::SRem { ty: result_ty, .. }
        | MirOperationKind::RotateLeft { ty: result_ty, .. }
        | MirOperationKind::RotateRight { ty: result_ty, .. }
        | MirOperationKind::Select { ty: result_ty, .. }
        | MirOperationKind::Concat { ty: result_ty, .. }
        | MirOperationKind::Extract { ty: result_ty, .. }
        | MirOperationKind::Not { ty: result_ty, .. }
        | MirOperationKind::Neg { ty: result_ty, .. }
        | MirOperationKind::Popcount { ty: result_ty, .. }
        | MirOperationKind::CountLeadingZeros { ty: result_ty, .. }
        | MirOperationKind::CountTrailingZeros { ty: result_ty, .. }
        | MirOperationKind::Load { ty: result_ty, .. }
        | MirOperationKind::AddressOf { ty: result_ty, .. }
        | MirOperationKind::Cast { ty: result_ty, .. }
        | MirOperationKind::Icmp { ty: result_ty, .. }
        | MirOperationKind::Fcmp { ty: result_ty, .. } => *result_ty = ty.clone(),
        MirOperationKind::Call { result_types, .. }
        | MirOperationKind::Intrinsic { result_types, .. } => {
            if let Some(first) = result_types.first_mut() {
                *first = ty.clone();
            }
        }
        MirOperationKind::Store { .. } | MirOperationKind::MemoryCopy { .. } => {}
    }
}

fn rewrite_value_types_in_operation(kind: &mut MirOperationKind, name: &str, ty: &MirType) {
    match kind {
        MirOperationKind::Copy { value, .. }
        | MirOperationKind::Extract { value, .. }
        | MirOperationKind::Not { value, .. }
        | MirOperationKind::Neg { value, .. }
        | MirOperationKind::Popcount { value, .. }
        | MirOperationKind::CountLeadingZeros { value, .. }
        | MirOperationKind::CountTrailingZeros { value, .. }
        | MirOperationKind::Load { address: value, .. }
        | MirOperationKind::AddressOf { address: value, .. }
        | MirOperationKind::Cast { value, .. } => rewrite_named_value_type(value, name, ty),
        MirOperationKind::Add { lhs, rhs, .. }
        | MirOperationKind::Sub { lhs, rhs, .. }
        | MirOperationKind::Mul { lhs, rhs, .. }
        | MirOperationKind::FAdd { lhs, rhs, .. }
        | MirOperationKind::FSub { lhs, rhs, .. }
        | MirOperationKind::FMul { lhs, rhs, .. }
        | MirOperationKind::FDiv { lhs, rhs, .. }
        | MirOperationKind::And { lhs, rhs, .. }
        | MirOperationKind::Or { lhs, rhs, .. }
        | MirOperationKind::Xor { lhs, rhs, .. }
        | MirOperationKind::Shl { lhs, rhs, .. }
        | MirOperationKind::LShr { lhs, rhs, .. }
        | MirOperationKind::AShr { lhs, rhs, .. }
        | MirOperationKind::UDiv { lhs, rhs, .. }
        | MirOperationKind::SDiv { lhs, rhs, .. }
        | MirOperationKind::URem { lhs, rhs, .. }
        | MirOperationKind::SRem { lhs, rhs, .. }
        | MirOperationKind::RotateLeft { lhs, rhs, .. }
        | MirOperationKind::RotateRight { lhs, rhs, .. }
        | MirOperationKind::Icmp { lhs, rhs, .. }
        | MirOperationKind::Fcmp { lhs, rhs, .. } => {
            rewrite_named_value_type(lhs, name, ty);
            rewrite_named_value_type(rhs, name, ty);
        }
        MirOperationKind::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            rewrite_named_value_type(condition, name, ty);
            rewrite_named_value_type(when_true, name, ty);
            rewrite_named_value_type(when_false, name, ty);
        }
        MirOperationKind::Concat { parts, .. }
        | MirOperationKind::Intrinsic {
            arguments: parts, ..
        } => {
            for part in parts {
                rewrite_named_value_type(part, name, ty);
            }
        }
        MirOperationKind::Store { address, value, .. } => {
            rewrite_named_value_type(address, name, ty);
            rewrite_named_value_type(value, name, ty);
        }
        MirOperationKind::MemoryCopy {
            src_address,
            dst_address,
            count,
            decrement,
            ..
        } => {
            rewrite_named_value_type(src_address, name, ty);
            rewrite_named_value_type(dst_address, name, ty);
            rewrite_named_value_type(count, name, ty);
            rewrite_named_value_type(decrement, name, ty);
        }
        MirOperationKind::Call {
            target, arguments, ..
        } => {
            match target {
                MirControlTarget::FunctionIndirect(value)
                | MirControlTarget::BlockIndirect(value) => {
                    rewrite_named_value_type(value, name, ty)
                }
                MirControlTarget::Direct(_) => {}
            }
            for argument in arguments {
                rewrite_named_value_type(argument, name, ty);
            }
        }
    }
}

fn rewrite_value_types_in_terminator(terminator: &mut MirTerminator, name: &str, ty: &MirType) {
    match terminator {
        MirTerminator::Jump { target, arguments } => {
            rewrite_control_target_value_type(target, name, ty);
            for argument in arguments {
                rewrite_named_value_type(argument, name, ty);
            }
        }
        MirTerminator::CondBr {
            condition,
            then_target,
            then_arguments,
            else_target,
            else_arguments,
        } => {
            rewrite_named_value_type(condition, name, ty);
            rewrite_control_target_value_type(then_target, name, ty);
            rewrite_control_target_value_type(else_target, name, ty);
            for argument in then_arguments {
                rewrite_named_value_type(argument, name, ty);
            }
            for argument in else_arguments {
                rewrite_named_value_type(argument, name, ty);
            }
        }
        MirTerminator::Return { values } => {
            for value in values {
                rewrite_named_value_type(value, name, ty);
            }
        }
        MirTerminator::Trap | MirTerminator::Unreachable => {}
    }
}

fn rewrite_control_target_value_type(target: &mut MirControlTarget, name: &str, ty: &MirType) {
    match target {
        MirControlTarget::FunctionIndirect(value) | MirControlTarget::BlockIndirect(value) => {
            rewrite_named_value_type(value, name, ty);
        }
        MirControlTarget::Direct(_) => {}
    }
}

fn rewrite_named_value_type(value: &mut MirValue, name: &str, ty: &MirType) {
    if let MirValue::Named {
        name: value_name,
        ty: value_ty,
    } = value
        && value_name == name
    {
        *value_ty = ty.clone();
    }
}

fn merge_observed_type(slot: &mut Option<MirType>, ty: MirType) {
    match slot {
        None => *slot = Some(ty),
        Some(existing) if *existing == ty => {}
        Some(existing) => merge_mir_type(existing, ty),
    }
}

fn merge_mir_type(existing: &mut MirType, ty: MirType) {
    match (existing, ty) {
        (MirType::Integer(existing_bits), MirType::Integer(bits)) => {
            *existing_bits = (*existing_bits).max(bits);
        }
        (MirType::Float(existing_bits), MirType::Float(bits)) => {
            *existing_bits = (*existing_bits).max(bits);
        }
        (MirType::Pointer { pointee: existing }, MirType::Pointer { pointee }) => {
            merge_mir_type(existing.as_mut(), *pointee);
        }
        (
            MirType::Function {
                parameters: existing_parameters,
                returns: existing_returns,
            },
            MirType::Function {
                parameters,
                returns,
            },
        ) => {
            merge_mir_type_lists(existing_parameters, parameters);
            merge_mir_type_lists(existing_returns, returns);
        }
        (existing, ty) => {
            if matches!(existing, MirType::Void) {
                *existing = ty;
            }
        }
    }
}

fn merge_mir_type_lists(existing: &mut Vec<MirType>, incoming: Vec<MirType>) {
    if existing.len() < incoming.len() {
        existing.resize(incoming.len(), MirType::void());
    }
    for (index, ty) in incoming.into_iter().enumerate() {
        merge_mir_type(&mut existing[index], ty);
    }
}
