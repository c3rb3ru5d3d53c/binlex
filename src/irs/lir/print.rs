use crate::irs::lir::{
    LirAddressSpace, LirBlock, LirData, LirDiagnostic, LirEffect, LirEncoding, LirExpression,
    LirFenceKind, LirFunction, LirInstruction, LirModule, LirTerminator, LirTrapKind,
};

pub fn format_lir_instruction(lir: &LirInstruction) -> String {
    let context = crate::irs::mlir::context();
    lir_instruction_operation(&context, lir)
        .and_then(|op| op.to_string())
        .unwrap_or_else(|error| format!("// mlir print failed: {error}"))
}

pub fn format_lir_block(block: &LirBlock) -> String {
    let context = crate::irs::mlir::context();
    lir_block_operation(&context, block)
        .and_then(|op| op.to_string())
        .unwrap_or_else(|error| format!("// mlir print failed: {error}"))
}

pub fn format_lir_function(function: &LirFunction) -> String {
    let context = crate::irs::mlir::context();
    lir_function_operation(&context, function)
        .and_then(|op| op.to_string())
        .unwrap_or_else(|error| format!("// mlir print failed: {error}"))
}

pub fn format_lir_module(module: &LirModule) -> String {
    let context = crate::irs::mlir::context();
    lir_module_operation(&context, module)
        .and_then(|op| crate::irs::mlir::MlirDocument::from_context_and_ops(context, vec![op]))
        .and_then(|document| document.text())
        .unwrap_or_else(|error| format!("// mlir print failed: {error}"))
}

fn lir_instruction_operation(
    context: &mlir::Context,
    lir: &LirInstruction,
) -> mlir::Result<mlir::Operation> {
    let mut attrs = Vec::new();
    attrs.push(crate::irs::mlir::integer_attr(
        context,
        "version",
        i64::from(lir.version),
    ));
    attrs.push(crate::irs::mlir::string_attr(
        context,
        "status",
        &format!("{:?}", lir.status),
    ));
    if let Some(abi) = lir.abi.as_ref() {
        attrs.push(crate::irs::mlir::string_attr(context, "abi", &abi.name));
    }
    if let Some(encoding) = lir.encoding.as_ref() {
        push_encoding_attrs(context, &mut attrs, encoding);
    }
    if !lir.temporaries.is_empty() {
        let temporaries = lir
            .temporaries
            .iter()
            .map(|temporary| {
                let name = temporary.name.as_deref().unwrap_or("");
                format!("tmp{} {} : i{}", temporary.id, name, temporary.bits)
            })
            .collect::<Vec<_>>()
            .join("\n");
        attrs.push(crate::irs::mlir::string_attr(
            context,
            "temporaries",
            &temporaries,
        ));
    }
    if !lir.effects.is_empty() {
        let effects = lir
            .effects
            .iter()
            .map(format_effect)
            .collect::<Vec<_>>()
            .join("\n");
        attrs.push(crate::irs::mlir::string_attr(context, "effects", &effects));
    }
    attrs.push(crate::irs::mlir::string_attr(
        context,
        "terminator",
        &format_terminator(&lir.terminator),
    ));
    if !lir.diagnostics.is_empty() {
        let diagnostics = lir
            .diagnostics
            .iter()
            .map(format_diagnostic)
            .collect::<Vec<_>>()
            .join("\n");
        attrs.push(crate::irs::mlir::string_attr(
            context,
            "diagnostics",
            &diagnostics,
        ));
    }
    crate::irs::mlir::operation(context, "binlex.lir.instruction", attrs, Vec::new())
}

fn lir_block_operation(context: &mlir::Context, block: &LirBlock) -> mlir::Result<mlir::Operation> {
    let name = block.name.as_deref().unwrap_or("block");
    let ops = block
        .instructions
        .iter()
        .map(|instruction| lir_instruction_operation(context, instruction))
        .collect::<mlir::Result<Vec<_>>>()?;
    crate::irs::mlir::operation(
        context,
        "binlex.lir.block",
        vec![crate::irs::mlir::string_attr(context, "sym_name", name)],
        vec![crate::irs::mlir::region_with_ops(ops)],
    )
}

fn lir_function_operation(
    context: &mlir::Context,
    function: &LirFunction,
) -> mlir::Result<mlir::Operation> {
    let name = function.name.as_deref().unwrap_or("function");
    let mut attrs = vec![crate::irs::mlir::string_attr(context, "sym_name", name)];
    if let Some(abi) = function.abi.as_ref() {
        attrs.push(crate::irs::mlir::string_attr(context, "abi", &abi.name));
    }
    let ops = function
        .blocks
        .iter()
        .map(|block| lir_block_operation(context, block))
        .collect::<mlir::Result<Vec<_>>>()?;
    crate::irs::mlir::operation(
        context,
        "binlex.lir.function",
        attrs,
        vec![crate::irs::mlir::region_with_ops(ops)],
    )
}

pub(crate) fn lir_module_operation(
    context: &mlir::Context,
    module: &LirModule,
) -> mlir::Result<mlir::Operation> {
    let name = module.name.as_deref().unwrap_or("module");
    let mut ops = module
        .functions
        .iter()
        .map(|function| lir_function_operation(context, function))
        .collect::<mlir::Result<Vec<_>>>()?;
    for data in &module.data {
        ops.push(lir_data_operation(context, data)?);
    }
    crate::irs::mlir::operation(
        context,
        "binlex.lir.module",
        vec![crate::irs::mlir::string_attr(context, "sym_name", name)],
        vec![crate::irs::mlir::region_with_ops(ops)],
    )
}

fn push_encoding_attrs(
    context: &mlir::Context,
    attrs: &mut Vec<mlir::NamedAttribute>,
    encoding: &LirEncoding,
) {
    attrs.push(crate::irs::mlir::string_attr(
        context,
        "architecture",
        &encoding.architecture,
    ));
    attrs.push(crate::irs::mlir::string_attr(
        context,
        "mnemonic",
        &encoding.mnemonic,
    ));
    attrs.push(crate::irs::mlir::string_attr(
        context,
        "disassembly",
        &encoding.disassembly,
    ));
    attrs.push(crate::irs::mlir::string_attr(
        context,
        "address",
        &format!("0x{:x}", encoding.address),
    ));
    if !encoding.bytes.is_empty() {
        let bytes = encoding
            .bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        attrs.push(crate::irs::mlir::string_attr(context, "bytes", &bytes));
    }
}

fn format_effect(effect: &LirEffect) -> String {
    match effect {
        LirEffect::Set { dst, expression } => format!(
            "set {} = {}",
            format_location(dst),
            format_expression(expression)
        ),
        LirEffect::Store {
            space,
            addr,
            expression,
            bits,
        } => format!(
            "store {}[{}] = {} : i{}",
            format_address_space(space),
            format_expression(addr),
            format_expression(expression),
            bits
        ),
        LirEffect::MemorySet {
            space,
            addr,
            value,
            count,
            element_bits,
            decrement,
        } => format!(
            "memset {}[{}], value {}, count {}, element_bits {}, decrement {}",
            format_address_space(space),
            format_expression(addr),
            format_expression(value),
            format_expression(count),
            element_bits,
            format_expression(decrement)
        ),
        LirEffect::MemoryCopy {
            src_space,
            src_addr,
            dst_space,
            dst_addr,
            count,
            element_bits,
            decrement,
        } => format!(
            "memcpy {}[{}] -> {}[{}], count {}, element_bits {}, decrement {}",
            format_address_space(src_space),
            format_expression(src_addr),
            format_address_space(dst_space),
            format_expression(dst_addr),
            format_expression(count),
            element_bits,
            format_expression(decrement)
        ),
        LirEffect::AtomicCmpXchg {
            space,
            addr,
            expected,
            desired,
            bits,
            observed,
        } => format!(
            "cmpxchg {}[{}], expected {}, desired {} -> {} : i{}",
            format_address_space(space),
            format_expression(addr),
            format_expression(expected),
            format_expression(desired),
            format_location(observed),
            bits
        ),
        LirEffect::WriteProperty {
            reference,
            name,
            expression,
            bits,
        } => format!(
            "write_property {}.{} = {} : i{}",
            format_expression(reference),
            name,
            format_expression(expression),
            bits
        ),
        LirEffect::WriteElement {
            reference,
            index,
            expression,
            bits,
        } => format!(
            "write_element {}[{}] = {} : i{}",
            format_expression(reference),
            format_expression(index),
            format_expression(expression),
            bits
        ),
        LirEffect::Push { stack, expression } => {
            format!("push {} <- {}", stack, format_expression(expression))
        }
        LirEffect::Pop { stack, dst } => format!("pop {} -> {}", stack, format_location(dst)),
        LirEffect::Fence { kind } => format!("fence {}", format_fence_kind(kind.clone())),
        LirEffect::Trap { kind } => format!("trap {}", format_trap_kind(kind.clone())),
        LirEffect::Intrinsic {
            name,
            args,
            outputs,
        } => {
            let args = args
                .iter()
                .map(format_expression)
                .collect::<Vec<_>>()
                .join(", ");
            let outputs = outputs
                .iter()
                .map(format_location)
                .collect::<Vec<_>>()
                .join(", ");
            format!("intrinsic {}({}) -> [{}]", name, args, outputs)
        }
        LirEffect::Nop => "nop".to_string(),
    }
}

fn format_terminator(terminator: &LirTerminator) -> String {
    match terminator {
        LirTerminator::FallThrough => "fallthrough".to_string(),
        LirTerminator::Jump { target } => format!("jump {}", format_expression(target)),
        LirTerminator::Branch {
            condition,
            true_target,
            false_target,
        } => format!(
            "branch {} ? {} : {}",
            format_expression(condition),
            format_expression(true_target),
            format_expression(false_target)
        ),
        LirTerminator::Call {
            target,
            return_target,
            does_return,
        } => {
            let return_target = return_target
                .as_ref()
                .map(|target| format!(", return {}", format_expression(target)))
                .unwrap_or_default();
            let does_return = does_return
                .map(|value| format!(", does_return {}", value))
                .unwrap_or_default();
            format!(
                "call {}{}{}",
                format_expression(target),
                return_target,
                does_return
            )
        }
        LirTerminator::Return { expression } => expression
            .as_ref()
            .map(|expression| format!("return {}", format_expression(expression)))
            .unwrap_or_else(|| "return".to_string()),
        LirTerminator::Unreachable => "unreachable".to_string(),
        LirTerminator::Trap => "trap".to_string(),
    }
}

fn format_diagnostic(diagnostic: &LirDiagnostic) -> String {
    format!("{:?}: {}", diagnostic.kind, diagnostic.message)
}

fn lir_data_operation(context: &mlir::Context, data: &LirData) -> mlir::Result<mlir::Operation> {
    let bytes = data
        .bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    crate::irs::mlir::operation(
        context,
        "binlex.lir.data",
        vec![
            crate::irs::mlir::string_attr(context, "sym_name", &data.name),
            crate::irs::mlir::string_attr(context, "bytes", &bytes),
        ],
        Vec::new(),
    )
}

fn format_location(location: &crate::irs::lir::LirLocation) -> String {
    match location {
        crate::irs::lir::LirLocation::Register { name, .. }
        | crate::irs::lir::LirLocation::Flag { name, .. } => format!("%{}", name),
        crate::irs::lir::LirLocation::ProgramCounter { .. } => "%pc".to_string(),
        crate::irs::lir::LirLocation::Temporary { id, .. } => format!("%tmp{id}"),
        crate::irs::lir::LirLocation::Memory { space, addr, .. } => {
            format!(
                "{}[{}]",
                format_address_space(space),
                format_expression(addr)
            )
        }
        crate::irs::lir::LirLocation::IndexedMemory { name, index, .. } => {
            format!("{}[{}]", name, format_expression(index))
        }
        crate::irs::lir::LirLocation::StackMemory { name, offset, .. } => {
            format!("{}[{}]", name, offset)
        }
    }
}

fn format_expression(expression: &LirExpression) -> String {
    match expression {
        LirExpression::Const { value, bits } => format!("{value}:i{bits}"),
        LirExpression::Function { name, bits } => format!("@{name}:i{bits}"),
        LirExpression::DataAddress { name, bits } => format!("&data[{name}]:i{bits}"),
        LirExpression::Read(location) => format!("read {}", format_location(location)),
        LirExpression::AddressOf { location, bits } => {
            format!("address_of {} : i{}", format_location(location), bits)
        }
        LirExpression::Load { space, addr, bits } => format!(
            "load {}[{}] : i{}",
            format_address_space(space),
            format_expression(addr),
            bits
        ),
        LirExpression::Unary { op, arg, bits } => {
            format!("{:?}({}) : i{}", op, format_expression(arg), bits).to_lowercase()
        }
        LirExpression::Binary {
            op,
            left,
            right,
            bits,
        } => format!(
            "{:?}({}, {}) : i{}",
            op,
            format_expression(left),
            format_expression(right),
            bits
        )
        .to_lowercase(),
        LirExpression::Cast { op, arg, bits } => {
            format!("{:?}({}) : i{}", op, format_expression(arg), bits).to_lowercase()
        }
        LirExpression::Compare {
            op,
            left,
            right,
            bits,
        } => format!(
            "{:?}({}, {}) : i{}",
            op,
            format_expression(left),
            format_expression(right),
            bits
        )
        .to_lowercase(),
        LirExpression::Concat { parts, bits } => format!(
            "concat({}) : i{}",
            parts
                .iter()
                .map(format_expression)
                .collect::<Vec<_>>()
                .join(", "),
            bits
        ),
        LirExpression::Extract { arg, lsb, bits } => {
            format!("extract({}, {}, {})", format_expression(arg), lsb, bits)
        }
        LirExpression::Select {
            condition,
            when_true,
            when_false,
            bits,
        } => format!(
            "select({}, {}, {}) : i{}",
            format_expression(condition),
            format_expression(when_true),
            format_expression(when_false),
            bits
        ),
        LirExpression::Intrinsic { name, args, bits } => format!(
            "{}({}) : i{}",
            name,
            args.iter()
                .map(format_expression)
                .collect::<Vec<_>>()
                .join(", "),
            bits
        ),
        LirExpression::Undefined { bits } => format!("undef:i{bits}"),
        LirExpression::Poison { bits } => format!("poison:i{bits}"),
        LirExpression::Null { bits } => format!("null:i{bits}"),
        LirExpression::Allocate { kind, bits } => format!("allocate {} : i{}", kind, bits),
        LirExpression::ReadProperty {
            reference,
            name,
            bits,
        } => format!(
            "read_property {}.{} : i{}",
            format_expression(reference),
            name,
            bits
        ),
        LirExpression::ReadElement {
            reference,
            index,
            bits,
        } => format!(
            "read_element {}[{}] : i{}",
            format_expression(reference),
            format_expression(index),
            bits
        ),
    }
}

fn format_address_space(space: &LirAddressSpace) -> String {
    format!("{space:?}").to_lowercase()
}

fn format_fence_kind(kind: LirFenceKind) -> String {
    format!("{kind:?}").to_lowercase()
}

fn format_trap_kind(kind: LirTrapKind) -> String {
    format!("{kind:?}").to_lowercase()
}
