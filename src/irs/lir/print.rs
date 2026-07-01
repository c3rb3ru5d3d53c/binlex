use crate::irs::lir::{
    LirAddressSpace, LirBlock, LirData, LirEffect, LirExpression, LirFenceKind, LirFunction,
    LirInstruction, LirModule, LirTerminator, LirTrapKind,
};

pub fn format_lir_instruction(lir: &LirInstruction) -> String {
    format_instruction_lines(lir).join("\n")
}

pub fn format_lir_block(block: &LirBlock) -> String {
    block
        .instructions
        .iter()
        .flat_map(format_instruction_lines)
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn format_lir_function(function: &LirFunction) -> String {
    function
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .flat_map(format_instruction_lines)
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn format_lir_module(module: &LirModule) -> String {
    module
        .functions
        .iter()
        .flat_map(|function| function.blocks.iter())
        .flat_map(|block| block.instructions.iter())
        .flat_map(format_instruction_lines)
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn format_lir_effect(effect: &LirEffect) -> String {
    format_effect(effect)
}

fn format_instruction_lines(lir: &LirInstruction) -> Vec<String> {
    let mut lines = lir.effects.iter().map(format_effect).collect::<Vec<_>>();
    if !matches!(lir.terminator, LirTerminator::FallThrough) {
        lines.push(format_terminator(&lir.terminator));
    }
    lines
}

pub fn format_lir_instruction_mlir(lir: &LirInstruction) -> String {
    let context = crate::irs::mlir::context();
    lir_instruction_operation(&context, lir)
        .and_then(|op| op.to_string())
        .unwrap_or_else(|error| format!("// mlir print failed: {error}"))
}

pub fn format_lir_block_mlir(block: &LirBlock) -> String {
    let context = crate::irs::mlir::context();
    lir_block_operation(&context, block)
        .and_then(|op| op.to_string())
        .unwrap_or_else(|error| format!("// mlir print failed: {error}"))
}

pub fn format_lir_function_mlir(function: &LirFunction) -> String {
    let context = crate::irs::mlir::context();
    lir_function_operation(&context, function)
        .and_then(|op| op.to_string())
        .unwrap_or_else(|error| format!("// mlir print failed: {error}"))
}

pub fn format_lir_module_mlir(module: &LirModule) -> String {
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
    attrs.push(crate::irs::mlir::string_attr(
        context,
        "status",
        &format!("{:?}", lir.status),
    ));
    if let Some(address) = lir.address {
        attrs.push(crate::irs::mlir::string_attr(
            context,
            "address",
            &format!("0x{address:x}"),
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
    let attrs = vec![crate::irs::mlir::string_attr(context, "sym_name", name)];
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

fn format_effect(effect: &LirEffect) -> String {
    match effect {
        LirEffect::Phi { dst, sources } => {
            let sources = sources
                .iter()
                .map(|source| format_expression(&source.value))
                .collect::<Vec<_>>()
                .join(", ");
            format!("{} = phi({})", format_location(dst), sources)
        }
        LirEffect::Set { dst, expression } => {
            format!(
                "{} = {}",
                format_location(dst),
                format_expression(expression)
            )
        }
        LirEffect::Store {
            space,
            addr,
            expression,
            bits,
        } => format!(
            "{} = {}",
            format_memory(space, *bits, addr),
            format_expression(expression),
        ),
        LirEffect::MemorySet {
            space,
            addr,
            value,
            count,
            element_bits,
            decrement,
        } => format!(
            "memset({}, {}, {}, decrement={})",
            format_memory(space, *element_bits, addr),
            format_expression(value),
            format_expression(count),
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
            "memcpy({}, {}, {}, decrement={})",
            format_memory(dst_space, *element_bits, dst_addr),
            format_memory(src_space, *element_bits, src_addr),
            format_expression(count),
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
            "{} = cmpxchg({}, {}, {})",
            format_location(observed),
            format_memory(space, *bits, addr),
            format_expression(expected),
            format_expression(desired),
        ),
        LirEffect::WriteProperty {
            reference,
            name,
            expression,
            ..
        } => format!(
            "{}.{} = {}",
            format_expression(reference),
            name,
            format_expression(expression)
        ),
        LirEffect::WriteElement {
            reference,
            index,
            expression,
            ..
        } => format!(
            "{}[{}] = {}",
            format_expression(reference),
            format_expression(index),
            format_expression(expression),
        ),
        LirEffect::Push { stack, expression } => {
            format!("{}.push({})", stack, format_expression(expression))
        }
        LirEffect::Pop { stack, dst } => {
            format!("{} = {}.pop()", format_location(dst), stack)
        }
        LirEffect::Fence { kind } => format!("fence({})", format_fence_kind(kind.clone())),
        LirEffect::Trap { kind } => format!("trap({})", format_trap_kind(kind.clone())),
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
            let call = format!("{}({})", name, args);
            match outputs.len() {
                0 => call,
                1 => format!("{} = {}", outputs, call),
                _ => format!("[{}] = {}", outputs, call),
            }
        }
        LirEffect::Nop => "nop".to_string(),
    }
}

fn format_terminator(terminator: &LirTerminator) -> String {
    match terminator {
        LirTerminator::FallThrough => "fallthrough".to_string(),
        LirTerminator::Jump { target } => {
            let keyword = match target {
                LirExpression::Const { .. } | LirExpression::Function { .. } => "goto",
                _ => "jump",
            };
            format!("{} {}", keyword, format_expression(target))
        }
        LirTerminator::Branch {
            condition,
            true_target,
            false_target,
        } => format!(
            "if {} then {} else {}",
            format_expression(condition),
            format_expression(true_target),
            format_expression(false_target)
        ),
        LirTerminator::Call {
            target,
            return_target: _,
            does_return: _,
        } => format!("call {}", format_expression(target)),
        LirTerminator::Return { expression } => expression
            .as_ref()
            .map(|expression| format!("return {}", format_expression(expression)))
            .unwrap_or_else(|| "return".to_string()),
        LirTerminator::Unreachable => "unreachable".to_string(),
        LirTerminator::Trap => "trap".to_string(),
    }
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
        | crate::irs::lir::LirLocation::Flag { name, .. } => name.to_lowercase(),
        crate::irs::lir::LirLocation::ProgramCounter { .. } => "pc".to_string(),
        crate::irs::lir::LirLocation::Temporary { id, .. } => format!("tmp{id}"),
        crate::irs::lir::LirLocation::Memory { space, addr, bits } => {
            format_memory(space, *bits, addr)
        }
        crate::irs::lir::LirLocation::IndexedMemory { name, index, .. } => {
            format!("{}[{}]", name, format_expression(index))
        }
        crate::irs::lir::LirLocation::StackMemory { name, offset, .. } => {
            format!("{}[{}]", name, format_hex(u128::from(*offset)))
        }
    }
}

fn format_expression(expression: &LirExpression) -> String {
    match expression {
        LirExpression::Const { value, bits } => format_hex_width(*value, *bits),
        LirExpression::Function { name, .. } => format!("@{name}"),
        LirExpression::DataAddress { name, .. } => format!("&data[{name}]"),
        LirExpression::Read(location) => format_location(location),
        LirExpression::AddressOf { location, .. } => {
            format!("&{}", format_location(location))
        }
        LirExpression::Load { space, addr, bits } => format_memory(space, *bits, addr),
        LirExpression::Unary { op, arg, .. } => format_unary_expression(op, arg),
        LirExpression::Binary {
            op, left, right, ..
        } => format_binary_expression(op, left, right),
        LirExpression::Cast { op, arg, bits } => format_cast_expression(op, arg, *bits),
        LirExpression::Compare {
            op, left, right, ..
        } => format_compare_expression(op, left, right),
        LirExpression::Concat { parts, .. } => format!(
            "concat({})",
            parts
                .iter()
                .map(format_expression)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        LirExpression::Extract { arg, lsb, bits } => {
            format!("extract({}, {}, {})", format_expression(arg), lsb, bits)
        }
        LirExpression::Select {
            condition,
            when_true,
            when_false,
            ..
        } => format!(
            "{} ? {} : {}",
            format_expression(condition),
            format_expression(when_true),
            format_expression(when_false),
        ),
        LirExpression::Intrinsic { name, args, .. } => format!(
            "{}({})",
            name,
            args.iter()
                .map(format_expression)
                .collect::<Vec<_>>()
                .join(", "),
        ),
        LirExpression::Undefined { .. } => "undef".to_string(),
        LirExpression::Poison { .. } => "poison".to_string(),
        LirExpression::Null { .. } => "null".to_string(),
        LirExpression::Allocate { kind, .. } => format!("alloc({})", kind),
        LirExpression::ReadProperty {
            reference, name, ..
        } => format!("{}.{}", format_expression(reference), name),
        LirExpression::ReadElement {
            reference, index, ..
        } => format!(
            "{}[{}]",
            format_expression(reference),
            format_expression(index),
        ),
    }
}

fn format_memory(space: &LirAddressSpace, bits: u16, addr: &LirExpression) -> String {
    let addr = format_expression(addr);
    match space {
        LirAddressSpace::Default => format!("@{}[{}]", bits, addr),
        _ => format!("{}@{}[{}]", format_address_space(space), bits, addr),
    }
}

fn format_unary_expression(op: &crate::irs::lir::LirOperationUnary, arg: &LirExpression) -> String {
    let arg = format_expression(arg);
    match op {
        crate::irs::lir::LirOperationUnary::Not => format!("~{}", arg),
        crate::irs::lir::LirOperationUnary::Neg => format!("-{}", arg),
        _ => format!("{}({})", format!("{op:?}").to_lowercase(), arg),
    }
}

fn format_binary_expression(
    op: &crate::irs::lir::LirOperationBinary,
    left: &LirExpression,
    right: &LirExpression,
) -> String {
    if matches!(op, crate::irs::lir::LirOperationBinary::And) && left == right {
        return format_expression(left);
    }

    let left = format_expression(left);
    let right = format_expression(right);
    let symbol = match op {
        crate::irs::lir::LirOperationBinary::Add => "+",
        crate::irs::lir::LirOperationBinary::AddWithCarry => "+c",
        crate::irs::lir::LirOperationBinary::Sub => "-",
        crate::irs::lir::LirOperationBinary::SubWithBorrow => "-b",
        crate::irs::lir::LirOperationBinary::Mul => "*",
        crate::irs::lir::LirOperationBinary::FAdd => "+f",
        crate::irs::lir::LirOperationBinary::FSub => "-f",
        crate::irs::lir::LirOperationBinary::FMul => "*f",
        crate::irs::lir::LirOperationBinary::FDiv => "/f",
        crate::irs::lir::LirOperationBinary::UMulHigh => "*hi_u",
        crate::irs::lir::LirOperationBinary::SMulHigh => "*hi_s",
        crate::irs::lir::LirOperationBinary::UDiv => "/u",
        crate::irs::lir::LirOperationBinary::SDiv => "/s",
        crate::irs::lir::LirOperationBinary::URem => "%u",
        crate::irs::lir::LirOperationBinary::SRem => "%s",
        crate::irs::lir::LirOperationBinary::And => "&",
        crate::irs::lir::LirOperationBinary::Or => "|",
        crate::irs::lir::LirOperationBinary::Xor => "^",
        crate::irs::lir::LirOperationBinary::Shl => "<<",
        crate::irs::lir::LirOperationBinary::LShr => ">>u",
        crate::irs::lir::LirOperationBinary::AShr => ">>s",
        crate::irs::lir::LirOperationBinary::RotateLeft => "rol",
        crate::irs::lir::LirOperationBinary::RotateRight => "ror",
        crate::irs::lir::LirOperationBinary::MinUnsigned => "min_u",
        crate::irs::lir::LirOperationBinary::MinSigned => "min_s",
        crate::irs::lir::LirOperationBinary::MaxUnsigned => "max_u",
        crate::irs::lir::LirOperationBinary::MaxSigned => "max_s",
    };
    match symbol {
        "rol" | "ror" | "min_u" | "min_s" | "max_u" | "max_s" => {
            format!("{}({}, {})", symbol, left, right)
        }
        _ => format!("{} {} {}", left, symbol, right),
    }
}

fn format_cast_expression(
    op: &crate::irs::lir::LirOperationCast,
    arg: &LirExpression,
    bits: u16,
) -> String {
    let name = match op {
        crate::irs::lir::LirOperationCast::ZeroExtend => "zext",
        crate::irs::lir::LirOperationCast::SignExtend => "sext",
        crate::irs::lir::LirOperationCast::Truncate => "trunc",
        crate::irs::lir::LirOperationCast::Bitcast => "bitcast",
        crate::irs::lir::LirOperationCast::IntToFloat => "int_to_float",
        crate::irs::lir::LirOperationCast::UIntToFloat => "uint_to_float",
        crate::irs::lir::LirOperationCast::FloatToInt => "float_to_int",
        crate::irs::lir::LirOperationCast::FloatToUInt => "float_to_uint",
        crate::irs::lir::LirOperationCast::FloatExtend => "fext",
        crate::irs::lir::LirOperationCast::FloatTruncate => "ftrunc",
    };
    format!("{}{}({})", name, bits, format_expression(arg))
}

fn format_compare_expression(
    op: &crate::irs::lir::LirOperationCompare,
    left: &LirExpression,
    right: &LirExpression,
) -> String {
    let symbol = match op {
        crate::irs::lir::LirOperationCompare::Eq => "==",
        crate::irs::lir::LirOperationCompare::Ne => "!=",
        crate::irs::lir::LirOperationCompare::Ult => "<u",
        crate::irs::lir::LirOperationCompare::Ule => "<=u",
        crate::irs::lir::LirOperationCompare::Ugt => ">u",
        crate::irs::lir::LirOperationCompare::Uge => ">=u",
        crate::irs::lir::LirOperationCompare::Slt => "<s",
        crate::irs::lir::LirOperationCompare::Sle => "<=s",
        crate::irs::lir::LirOperationCompare::Sgt => ">s",
        crate::irs::lir::LirOperationCompare::Sge => ">=s",
        crate::irs::lir::LirOperationCompare::Oeq => "==f",
        crate::irs::lir::LirOperationCompare::One => "!=f",
        crate::irs::lir::LirOperationCompare::Olt => "<f",
        crate::irs::lir::LirOperationCompare::Ole => "<=f",
        crate::irs::lir::LirOperationCompare::Ogt => ">f",
        crate::irs::lir::LirOperationCompare::Oge => ">=f",
        crate::irs::lir::LirOperationCompare::Ueq => "==uf",
        crate::irs::lir::LirOperationCompare::Une => "!=uf",
        crate::irs::lir::LirOperationCompare::UltFp => "<uf",
        crate::irs::lir::LirOperationCompare::UleFp => "<=uf",
        crate::irs::lir::LirOperationCompare::UgtFp => ">uf",
        crate::irs::lir::LirOperationCompare::UgeFp => ">=uf",
        crate::irs::lir::LirOperationCompare::Ordered => {
            return format!(
                "ordered({}, {})",
                format_expression(left),
                format_expression(right)
            );
        }
        crate::irs::lir::LirOperationCompare::Unordered => {
            return format!(
                "unordered({}, {})",
                format_expression(left),
                format_expression(right)
            );
        }
    };
    format!(
        "{} {} {}",
        format_expression(left),
        symbol,
        format_expression(right)
    )
}

fn format_hex(value: u128) -> String {
    format!("0x{value:x}")
}

fn format_hex_width(value: u128, bits: u16) -> String {
    if bits >= 128 {
        return format_hex(value);
    }
    if bits == 0 {
        return format_hex(value);
    }
    let mask = (1u128 << bits) - 1;
    format_hex(value & mask)
}

fn format_address_space(space: &LirAddressSpace) -> String {
    match space {
        LirAddressSpace::CpuMemory { name }
        | LirAddressSpace::Segment { name }
        | LirAddressSpace::Named { name } => name.to_lowercase(),
        _ => format!("{space:?}").to_lowercase(),
    }
}

fn format_fence_kind(kind: LirFenceKind) -> String {
    format!("{kind:?}").to_lowercase()
}

fn format_trap_kind(kind: LirTrapKind) -> String {
    format!("{kind:?}").to_lowercase()
}

#[cfg(test)]
mod tests {
    use crate::irs::lir::{
        LirAddressSpace, LirBlock, LirEffect, LirExpression, LirInstruction, LirLocation,
        LirOperationBinary, LirOperationCompare, LirStatus, LirTerminator, format_lir_block,
        format_lir_instruction,
    };

    #[test]
    fn effect_printing_uses_lowercase_miasm_like_style() {
        let rax = LirLocation::Register {
            name: "rax".to_string(),
            bits: 64,
        };
        let rbx = LirLocation::Register {
            name: "rbx".to_string(),
            bits: 64,
        };
        let rcx = LirLocation::Register {
            name: "rcx".to_string(),
            bits: 64,
        };
        let eax = LirLocation::Register {
            name: "eax".to_string(),
            bits: 32,
        };
        let rdx = LirLocation::Register {
            name: "rdx".to_string(),
            bits: 64,
        };
        let load_addr = LirExpression::Binary {
            op: LirOperationBinary::Add,
            left: Box::new(LirExpression::Read(Box::new(rbx.clone()))),
            right: Box::new(LirExpression::Const {
                value: 0x10,
                bits: 64,
            }),
            bits: 64,
        };
        let instruction = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![
                LirEffect::Set {
                    dst: rax.clone(),
                    expression: LirExpression::Load {
                        space: LirAddressSpace::Default,
                        addr: Box::new(load_addr),
                        bits: 64,
                    },
                },
                LirEffect::Store {
                    space: LirAddressSpace::Default,
                    addr: LirExpression::Read(Box::new(rcx)),
                    expression: LirExpression::Read(Box::new(eax)),
                    bits: 32,
                },
                LirEffect::Set {
                    dst: rdx,
                    expression: LirExpression::Binary {
                        op: LirOperationBinary::And,
                        left: Box::new(LirExpression::Read(Box::new(rax))),
                        right: Box::new(LirExpression::Const {
                            value: 0xff,
                            bits: 64,
                        }),
                        bits: 64,
                    },
                },
            ],
            terminator: LirTerminator::FallThrough,
        };

        assert_eq!(
            format_lir_instruction(&instruction),
            "rax = @64[rbx + 0x10]\n@32[rcx] = eax\nrdx = rax & 0xff"
        );
    }

    #[test]
    fn instruction_printing_appends_binary_ninja_inspired_branch_terminator() {
        let zf = LirLocation::Flag {
            name: "zf".to_string(),
            bits: 1,
        };
        let rax = LirLocation::Register {
            name: "rax".to_string(),
            bits: 64,
        };
        let instruction = LirInstruction {
            address: Some(0x401000),
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: zf.clone(),
                expression: LirExpression::Compare {
                    op: LirOperationCompare::Eq,
                    left: Box::new(LirExpression::Read(Box::new(rax))),
                    right: Box::new(LirExpression::Const { value: 0, bits: 64 }),
                    bits: 1,
                },
            }],
            terminator: LirTerminator::Branch {
                condition: LirExpression::Read(Box::new(zf)),
                true_target: LirExpression::Const {
                    value: 0x401040,
                    bits: 64,
                },
                false_target: LirExpression::Const {
                    value: 0x401020,
                    bits: 64,
                },
            },
        };

        assert_eq!(
            format_lir_instruction(&instruction),
            "zf = rax == 0x0\nif zf then 0x401040 else 0x401020"
        );
    }

    #[test]
    fn expression_printing_simplifies_self_and_operands() {
        let rdi = LirLocation::Register {
            name: "rdi.0".to_string(),
            bits: 64,
        };
        let self_and = LirExpression::Binary {
            op: LirOperationBinary::And,
            left: Box::new(LirExpression::Read(Box::new(rdi.clone()))),
            right: Box::new(LirExpression::Read(Box::new(rdi))),
            bits: 64,
        };
        let instruction = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Flag {
                    name: "zf.1".to_string(),
                    bits: 1,
                },
                expression: LirExpression::Compare {
                    op: LirOperationCompare::Eq,
                    left: Box::new(self_and),
                    right: Box::new(LirExpression::Const { value: 0, bits: 64 }),
                    bits: 1,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };

        assert_eq!(format_lir_instruction(&instruction), "zf.1 = rdi.0 == 0x0");
    }

    #[test]
    fn expression_printing_masks_constants_to_their_width() {
        let rbp = LirLocation::Register {
            name: "rbp.1".to_string(),
            bits: 64,
        };
        let instruction = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Set {
                dst: LirLocation::Flag {
                    name: "zf.13".to_string(),
                    bits: 1,
                },
                expression: LirExpression::Compare {
                    op: LirOperationCompare::Eq,
                    left: Box::new(LirExpression::Read(Box::new(rbp))),
                    right: Box::new(LirExpression::Const {
                        value: u128::MAX,
                        bits: 64,
                    }),
                    bits: 1,
                },
            }],
            terminator: LirTerminator::FallThrough,
        };

        assert_eq!(
            format_lir_instruction(&instruction),
            "zf.13 = rbp.1 == 0xffffffffffffffff"
        );
    }

    #[test]
    fn instruction_printing_renders_direct_jump_as_goto_and_indirect_jump_as_jump() {
        let direct = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: Vec::new(),
            terminator: LirTerminator::Jump {
                target: LirExpression::Const {
                    value: 0x401200,
                    bits: 64,
                },
            },
        };
        let indirect = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: Vec::new(),
            terminator: LirTerminator::Jump {
                target: LirExpression::Read(Box::new(LirLocation::Register {
                    name: "rax".to_string(),
                    bits: 64,
                })),
            },
        };

        assert_eq!(format_lir_instruction(&direct), "goto 0x401200");
        assert_eq!(format_lir_instruction(&indirect), "jump rax");
    }

    #[test]
    fn instruction_printing_renders_call_without_return_annotations() {
        let rsp = LirLocation::Register {
            name: "rsp".to_string(),
            bits: 64,
        };
        let return_target = LirExpression::Const {
            value: 0x401005,
            bits: 64,
        };
        let instruction = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![
                LirEffect::Set {
                    dst: rsp.clone(),
                    expression: LirExpression::Binary {
                        op: LirOperationBinary::Sub,
                        left: Box::new(LirExpression::Read(Box::new(rsp.clone()))),
                        right: Box::new(LirExpression::Const { value: 8, bits: 64 }),
                        bits: 64,
                    },
                },
                LirEffect::Store {
                    space: LirAddressSpace::Default,
                    addr: LirExpression::Read(Box::new(rsp)),
                    expression: return_target.clone(),
                    bits: 64,
                },
            ],
            terminator: LirTerminator::Call {
                target: LirExpression::Const {
                    value: 0x402000,
                    bits: 64,
                },
                return_target: Some(return_target),
                does_return: Some(false),
            },
        };

        assert_eq!(
            format_lir_instruction(&instruction),
            "rsp = rsp - 0x8\n@64[rsp] = 0x401005\ncall 0x402000"
        );
    }

    #[test]
    fn instruction_printing_renders_return_terminator() {
        let instruction = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: Vec::new(),
            terminator: LirTerminator::Return {
                expression: Some(LirExpression::Read(Box::new(LirLocation::Register {
                    name: "rax".to_string(),
                    bits: 64,
                }))),
            },
        };

        assert_eq!(format_lir_instruction(&instruction), "return rax");
    }

    #[test]
    fn block_printing_preserves_all_effects_and_non_fallthrough_terminators() {
        let rax = LirLocation::Register {
            name: "rax".to_string(),
            bits: 64,
        };
        let block = LirBlock {
            name: None,
            instructions: vec![
                LirInstruction {
                    address: None,
                    status: LirStatus::Complete,
                    effects: vec![LirEffect::Set {
                        dst: rax.clone(),
                        expression: LirExpression::Const { value: 1, bits: 64 },
                    }],
                    terminator: LirTerminator::FallThrough,
                },
                LirInstruction {
                    address: None,
                    status: LirStatus::Complete,
                    effects: vec![LirEffect::Set {
                        dst: rax,
                        expression: LirExpression::Const { value: 2, bits: 64 },
                    }],
                    terminator: LirTerminator::Return { expression: None },
                },
            ],
        };

        assert_eq!(format_lir_block(&block), "rax = 0x1\nrax = 0x2\nreturn");
    }
}
