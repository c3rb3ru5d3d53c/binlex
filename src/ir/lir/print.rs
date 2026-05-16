use crate::ir::lir::{
    LirAddressSpace, LirBlock, LirData, LirDiagnostic, LirEffect, LirEncoding, LirExpression,
    LirFenceKind, LirFunction, LirInstruction, LirModule, LirTerminator, LirTrapKind,
};

pub fn format_lir_instruction(lir: &LirInstruction) -> String {
    let mut lines = Vec::new();
    let header = lir
        .encoding
        .as_ref()
        .map(|encoding| format!("lir.instruction @{:x} {{", encoding.address))
        .unwrap_or_else(|| "lir.instruction {".to_string());
    lines.push(header);

    if let Some(encoding) = lir.encoding.as_ref() {
        push_encoding(&mut lines, encoding);
    }

    if !lir.temporaries.is_empty() {
        lines.push(String::new());
        lines.push("  temporaries:".to_string());
        for temporary in &lir.temporaries {
            let name = temporary
                .name
                .as_ref()
                .map(|name| format!(" {}", name))
                .unwrap_or_default();
            lines.push(format!(
                "    tmp{}{} : i{}",
                temporary.id, name, temporary.bits
            ));
        }
    }

    if !lir.effects.is_empty() {
        lines.push(String::new());
        lines.push("  effects:".to_string());
        for effect in &lir.effects {
            lines.push(format!("    {}", format_effect(effect)));
        }
    }

    lines.push(String::new());
    lines.push("  terminator:".to_string());
    lines.push(format!("    {}", format_terminator(&lir.terminator)));

    if !lir.diagnostics.is_empty() {
        lines.push(String::new());
        lines.push("  diagnostics:".to_string());
        for diagnostic in &lir.diagnostics {
            lines.push(format!("    {}", format_diagnostic(diagnostic)));
        }
    }

    lines.push("}".to_string());
    lines.join("\n")
}

pub fn format_lir_block(block: &LirBlock) -> String {
    let name = block.name.as_deref().unwrap_or("block");
    let mut lines = vec![format!("lir.block @{name} {{")];
    for (index, instruction) in block.instructions.iter().enumerate() {
        if index > 0 {
            lines.push(String::new());
        }
        for line in format_lir_instruction(instruction).lines() {
            lines.push(format!("  {line}"));
        }
    }
    lines.push("}".to_string());
    lines.join("\n")
}

pub fn format_lir_function(function: &LirFunction) -> String {
    let name = function.name.as_deref().unwrap_or("function");
    let mut lines = vec![format!("lir.function @{name} {{")];
    if let Some(abi) = function.abi.as_ref() {
        lines.push(format!("  abi {}", abi.name));
    }
    for (index, block) in function.blocks.iter().enumerate() {
        if index > 0 || function.abi.is_some() {
            lines.push(String::new());
        }
        for line in format_lir_block(block).lines() {
            lines.push(format!("  {line}"));
        }
    }
    lines.push("}".to_string());
    lines.join("\n")
}

pub fn format_lir_module(module: &LirModule) -> String {
    let name = module.name.as_deref().unwrap_or("module");
    let mut lines = vec![format!("lir.module @{name} {{")];

    for (index, function) in module.functions.iter().enumerate() {
        if index > 0 {
            lines.push(String::new());
        }
        for line in format_lir_function(function).lines() {
            lines.push(format!("  {line}"));
        }
    }

    if !module.data.is_empty() {
        if !module.functions.is_empty() {
            lines.push(String::new());
        }
        lines.push("  lir.data {".to_string());
        for data in &module.data {
            lines.push(format!("    {}", format_data(data)));
        }
        lines.push("  }".to_string());
    }

    lines.push("}".to_string());
    lines.join("\n")
}

fn push_encoding(lines: &mut Vec<String>, encoding: &LirEncoding) {
    lines.push(format!("  architecture {}", encoding.architecture));
    lines.push(format!("  mnemonic {:?}", encoding.mnemonic));
    lines.push(format!("  disassembly {:?}", encoding.disassembly));
    if !encoding.bytes.is_empty() {
        let bytes = encoding
            .bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        lines.push(format!("  bytes {}", bytes));
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

fn format_data(data: &LirData) -> String {
    let bytes = data
        .bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    format!("{} [{}]", data.name, bytes)
}

fn format_location(location: &crate::ir::lir::LirLocation) -> String {
    match location {
        crate::ir::lir::LirLocation::Register { name, .. }
        | crate::ir::lir::LirLocation::Flag { name, .. } => format!("%{}", name),
        crate::ir::lir::LirLocation::ProgramCounter { .. } => "%pc".to_string(),
        crate::ir::lir::LirLocation::Temporary { id, .. } => format!("%tmp{id}"),
        crate::ir::lir::LirLocation::Memory { space, addr, .. } => {
            format!(
                "{}[{}]",
                format_address_space(space),
                format_expression(addr)
            )
        }
        crate::ir::lir::LirLocation::IndexedMemory { name, index, .. } => {
            format!("{}[{}]", name, format_expression(index))
        }
        crate::ir::lir::LirLocation::StackMemory { name, offset, .. } => {
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
