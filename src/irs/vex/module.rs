use std::io::{Error, ErrorKind};

use serde::{Deserialize, Serialize};

use crate::Configuration;
use crate::controlflow::{Block, Function, Instruction};
use crate::core::Architecture;
use crate::irs::lir::{
    Lir, LirAddressSpace, LirBlock, LirDiagnostic, LirEffect, LirExpression, LirFunction,
    LirLocation, LirModule, LirOperationBinary, LirOperationCast, LirOperationCompare,
    LirOperationUnary, LirTerminator,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct InstructionRequest {
    address: u64,
    bytes: Vec<u8>,
    lir: Lir,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BlockRequest {
    address: u64,
    instructions: Vec<InstructionRequest>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum Request {
    Instruction {
        architecture: Architecture,
        instruction: InstructionRequest,
    },
    Block {
        architecture: Architecture,
        block: BlockRequest,
    },
    Function {
        architecture: Architecture,
        address: u64,
        blocks: Vec<BlockRequest>,
    },
}

#[derive(Clone)]
pub struct VexModule {
    name: Option<String>,
    _config: Configuration,
    functions: Vec<VexFunction>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VexFunction {
    name: Option<String>,
    blocks: Vec<VexBlock>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VexBlock {
    name: Option<String>,
    statements: Vec<VexStatement>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VexStatement {
    text: String,
}

impl VexModule {
    pub fn new(name: Option<String>) -> Self {
        Self::with_config(name, Configuration::default())
    }

    pub fn with_config(name: Option<String>, config: Configuration) -> Self {
        Self {
            name,
            _config: config,
            functions: Vec::new(),
        }
    }

    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub fn functions(&self) -> &[VexFunction] {
        &self.functions
    }

    pub fn functions_mut(&mut self) -> &mut Vec<VexFunction> {
        &mut self.functions
    }

    pub fn append_function(&mut self, function: VexFunction) {
        self.functions.push(function);
    }

    pub fn from_lir(&mut self, lir: &LirModule, config: Configuration) -> Result<(), Error> {
        self.name = lir.name.clone();
        self._config = config;
        self.functions.clear();
        for (index, function) in lir.functions.iter().enumerate() {
            let function_name = function
                .name
                .clone()
                .or_else(|| lir.name.clone())
                .unwrap_or_else(|| format!("function_{index}"));
            self.functions.push(VexFunction::from_lir_function(
                Some(function_name),
                function,
            ));
        }
        Ok(())
    }

    pub fn populate_instruction(&mut self, instruction: &Instruction) -> Result<(), Error> {
        self.ensure_supported_architecture(instruction.architecture)?;
        let name = format!("instruction_{:x}", instruction.address);
        let request = self.instruction_request(instruction)?;
        let blocks = self.execute(Request::Instruction {
            architecture: instruction.architecture,
            instruction: request,
        })?;
        let mut function = VexFunction::new(Some(name));
        for (block_name, lines) in blocks {
            function.append_block(VexBlock::from_statement_lines(Some(block_name), lines));
        }
        self.functions.push(function);
        Ok(())
    }

    pub fn populate_block(&mut self, block: &Block<'_>) -> Result<(), Error> {
        let architecture = block.architecture();
        self.ensure_supported_architecture(architecture)?;
        let name = format!("block_{:x}", block.address());
        let request = self.block_request(block)?;
        let blocks = self.execute(Request::Block {
            architecture,
            block: request,
        })?;
        let mut function = VexFunction::new(Some(name));
        for (block_name, lines) in blocks {
            function.append_block(VexBlock::from_statement_lines(Some(block_name), lines));
        }
        self.functions.push(function);
        Ok(())
    }

    pub fn populate_function(&mut self, function: &Function<'_>) -> Result<(), Error> {
        let architecture = function.architecture();
        self.ensure_supported_architecture(architecture)?;
        let name = format!("function_{:x}", function.address());
        let blocks = function
            .blocks
            .values()
            .map(|block| self.block_request(block))
            .collect::<Result<Vec<_>, _>>()?;
        let block_lines = self.execute(Request::Function {
            architecture,
            address: function.address(),
            blocks,
        })?;
        let mut function = VexFunction::new(Some(name));
        for (name, lines) in block_lines {
            let mut block = VexBlock::new(Some(name));
            for line in lines {
                block.append_statement(VexStatement::new(line));
            }
            function.append_block(block);
        }
        self.functions.push(function);
        Ok(())
    }

    pub fn text(&self) -> String {
        self.functions
            .iter()
            .map(VexFunction::text)
            .collect::<Vec<_>>()
            .join("\n\n")
    }

    pub fn clear(&mut self) -> Result<(), Error> {
        self.functions.clear();
        Ok(())
    }

    pub fn print(&self) {
        println!("{}", self.text());
    }

    fn ensure_supported_architecture(&self, architecture: Architecture) -> Result<(), Error> {
        match architecture {
            Architecture::AMD64 | Architecture::I386 | Architecture::CIL => Ok(()),
            Architecture::ARM64 => Err(Error::new(
                ErrorKind::InvalidInput,
                format!("unsupported VEX architecture: {}", architecture),
            )),
            Architecture::UNKNOWN => Err(Error::new(
                ErrorKind::InvalidInput,
                format!("unsupported VEX architecture: {}", architecture),
            )),
        }
    }

    fn execute(&self, request: Request) -> Result<Vec<(String, Vec<String>)>, Error> {
        Ok(match request {
            Request::Instruction { instruction, .. } => {
                vec![(
                    format!("block_{:x}", instruction.address),
                    render_instruction_statements(&instruction),
                )]
            }
            Request::Block { block, .. } => {
                vec![(
                    format!("block_{:x}", block.address),
                    render_block_statements(&block),
                )]
            }
            Request::Function {
                address, blocks, ..
            } => render_function_blocks(address, &blocks),
        })
    }

    fn instruction_request(&self, instruction: &Instruction) -> Result<InstructionRequest, Error> {
        Ok(InstructionRequest {
            address: instruction.address,
            bytes: instruction.bytes.clone(),
            lir: instruction
                .lir
                .as_ref()
                .ok_or_else(|| {
                    Error::new(
                        ErrorKind::InvalidInput,
                        format!(
                            "instruction 0x{:x} is missing lir required for VEX lifting",
                            instruction.address
                        ),
                    )
                })?
                .clone(),
        })
    }

    fn block_request(&self, block: &Block<'_>) -> Result<BlockRequest, Error> {
        Ok(BlockRequest {
            address: block.address(),
            instructions: block
                .instructions()
                .into_iter()
                .map(|instruction| self.instruction_request(&instruction))
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

impl VexFunction {
    pub fn new(name: Option<String>) -> Self {
        Self {
            name,
            blocks: Vec::new(),
        }
    }

    fn from_lir_function(name: Option<String>, function: &LirFunction) -> Self {
        let mut result = Self::new(name);
        for (index, block) in function.blocks.iter().enumerate() {
            let block_name = block
                .name
                .clone()
                .unwrap_or_else(|| format!("block_{index}"));
            result.append_block(VexBlock::from_lir_block(Some(block_name), block));
        }
        result
    }

    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub fn blocks(&self) -> &[VexBlock] {
        &self.blocks
    }

    pub fn blocks_mut(&mut self) -> &mut Vec<VexBlock> {
        &mut self.blocks
    }

    pub fn append_block(&mut self, block: VexBlock) {
        self.blocks.push(block);
    }

    pub fn text(&self) -> String {
        let mut lines = Vec::new();
        if let Some(name) = &self.name {
            lines.push(format!("; function {name}"));
        }
        for block in &self.blocks {
            lines.push(block.text());
        }
        lines.join("\n")
    }

    pub fn print(&self) {
        println!("{}", self.text());
    }
}

impl VexBlock {
    pub fn new(name: Option<String>) -> Self {
        Self {
            name,
            statements: Vec::new(),
        }
    }

    fn from_statement_lines(name: Option<String>, lines: Vec<String>) -> Self {
        let mut block = Self::new(name);
        for line in lines {
            block.append_statement(VexStatement::new(line));
        }
        block
    }

    fn from_lir_block(name: Option<String>, block: &LirBlock) -> Self {
        Self::from_statement_lines(name, render_lir_block_statements(block))
    }

    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub fn statements(&self) -> &[VexStatement] {
        &self.statements
    }

    pub fn statements_mut(&mut self) -> &mut Vec<VexStatement> {
        &mut self.statements
    }

    pub fn append_statement(&mut self, statement: VexStatement) {
        self.statements.push(statement);
    }

    pub fn text(&self) -> String {
        let mut lines = Vec::new();
        if let Some(name) = &self.name {
            lines.push(format!("; block {name}"));
        }
        lines.push("IRSB {".to_string());
        lines.extend(
            self.statements
                .iter()
                .map(|statement| statement.text.clone()),
        );
        lines.push("}".to_string());
        lines.join("\n")
    }

    pub fn print(&self) {
        println!("{}", self.text());
    }
}

impl VexStatement {
    pub fn new(text: impl Into<String>) -> Self {
        Self { text: text.into() }
    }

    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn print(&self) {
        println!("{}", self.text);
    }
}

fn render_lir_block_statements(block: &LirBlock) -> Vec<String> {
    let mut lines = Vec::new();
    for instruction in &block.instructions {
        lines.extend(render_lir_instruction_body(instruction));
    }
    lines
}

fn render_lir_instruction_body(instruction: &Lir) -> Vec<String> {
    let address = instruction
        .encoding
        .as_ref()
        .map(|encoding| encoding.address)
        .unwrap_or(0);
    let byte_len = instruction
        .encoding
        .as_ref()
        .map(|encoding| encoding.bytes.len())
        .unwrap_or(0);
    let mut lines = vec![format!(
        "   ------ IMark(0x{:016x}, {}, 0) ------",
        address, byte_len
    )];

    for temp in &instruction.temporaries {
        let name = temp
            .name
            .as_deref()
            .map(|value| format!(" ; {}", value))
            .unwrap_or_default();
        lines.push(format!("   t{}:{}{}", temp.id, temp.bits, name));
    }

    for effect in &instruction.effects {
        lines.push(format!("   {}", render_effect(effect)));
    }

    for diagnostic in &instruction.diagnostics {
        lines.push(format!("   ; diag {}", render_diagnostic(diagnostic)));
    }

    lines.push(format!("   {}", render_terminator(&instruction.terminator)));
    lines
}

fn render_function_blocks(_address: u64, blocks: &[BlockRequest]) -> Vec<(String, Vec<String>)> {
    blocks
        .iter()
        .map(|block| {
            (
                format!("block_{:x}", block.address),
                render_block_statements(block),
            )
        })
        .collect()
}

fn render_block_statements(block: &BlockRequest) -> Vec<String> {
    let mut lines = Vec::new();
    for instruction in &block.instructions {
        lines.extend(render_instruction_body(instruction));
    }
    lines
}

fn render_instruction_statements(instruction: &InstructionRequest) -> Vec<String> {
    render_instruction_body(instruction)
}

fn render_instruction_body(instruction: &InstructionRequest) -> Vec<String> {
    let mut lines = vec![format!(
        "   ------ IMark(0x{:016x}, {}, 0) ------",
        instruction.address,
        instruction.bytes.len()
    )];

    for temp in &instruction.lir.temporaries {
        let name = temp
            .name
            .as_deref()
            .map(|value| format!(" ; {}", value))
            .unwrap_or_default();
        lines.push(format!("   t{}:{}{}", temp.id, temp.bits, name));
    }

    for effect in &instruction.lir.effects {
        lines.push(format!("   {}", render_effect(effect)));
    }

    for diagnostic in &instruction.lir.diagnostics {
        lines.push(format!("   ; diag {}", render_diagnostic(diagnostic)));
    }

    lines.push(format!(
        "   {}",
        render_terminator(&instruction.lir.terminator)
    ));
    lines
}

fn render_diagnostic(diagnostic: &LirDiagnostic) -> String {
    format!("{:?}: {}", diagnostic.kind, diagnostic.message)
}

fn render_effect(effect: &LirEffect) -> String {
    match effect {
        LirEffect::Set { dst, expression } => {
            format!(
                "{} = {}",
                render_location_write(dst),
                render_expression(expression)
            )
        }
        LirEffect::Store {
            space,
            addr,
            expression,
            bits,
        } => format!(
            "ST{}({}, {}) = {}",
            bits,
            render_address_space(space),
            render_expression(addr),
            render_expression(expression)
        ),
        LirEffect::MemorySet {
            space,
            addr,
            value,
            count,
            element_bits,
            decrement,
        } => format!(
            "DIRTY MEMSET{}({}, {}, {}, {}, {})",
            element_bits,
            render_address_space(space),
            render_expression(addr),
            render_expression(count),
            render_expression(value),
            render_expression(decrement)
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
            "DIRTY MEMCPY{}({}:{}, {}:{}, {}, {})",
            element_bits,
            render_address_space(src_space),
            render_expression(src_addr),
            render_address_space(dst_space),
            render_expression(dst_addr),
            render_expression(count),
            render_expression(decrement)
        ),
        LirEffect::AtomicCmpXchg {
            space,
            addr,
            expected,
            desired,
            bits,
            observed,
        } => format!(
            "{} = DIRTY ATOMIC_CMPXCHG{}({}, {}, {}, {})",
            render_location_write(observed),
            bits,
            render_address_space(space),
            render_expression(addr),
            render_expression(expected),
            render_expression(desired)
        ),
        LirEffect::WriteProperty {
            reference,
            name,
            expression,
            bits,
        } => format!(
            "WRITE_PROPERTY{}({}, {}, {})",
            bits,
            render_expression(reference),
            name,
            render_expression(expression)
        ),
        LirEffect::WriteElement {
            reference,
            index,
            expression,
            bits,
        } => format!(
            "WRITE_ELEMENT{}({}, {}, {})",
            bits,
            render_expression(reference),
            render_expression(index),
            render_expression(expression)
        ),
        LirEffect::Push { stack, expression } => {
            format!("PUSH({}, {})", stack, render_expression(expression))
        }
        LirEffect::Pop { stack, dst } => {
            format!("{} = POP({})", render_location_write(dst), stack)
        }
        LirEffect::Fence { kind } => format!("DIRTY fence({kind:?})"),
        LirEffect::Trap { kind } => format!("DIRTY trap({kind:?})"),
        LirEffect::Intrinsic {
            name,
            args,
            outputs,
        } => {
            let args = args
                .iter()
                .map(render_expression)
                .collect::<Vec<_>>()
                .join(", ");
            if outputs.is_empty() {
                format!("DIRTY {}({})", name, args)
            } else {
                let outputs = outputs
                    .iter()
                    .map(render_location_write)
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("{outputs} = DIRTY {name}({args})")
            }
        }
        LirEffect::Nop => "NOP".to_string(),
    }
}

fn render_terminator(terminator: &LirTerminator) -> String {
    match terminator {
        LirTerminator::FallThrough => "NEXT: fallthrough; Ijk_Boring".to_string(),
        LirTerminator::Jump { target } => {
            format!("NEXT: {}; Ijk_Boring", render_expression(target))
        }
        LirTerminator::Branch {
            condition,
            true_target,
            false_target,
        } => format!(
            "if ({}) {{ NEXT: {} }} else {{ NEXT: {} }}; Ijk_Boring",
            render_expression(condition),
            render_expression(true_target),
            render_expression(false_target)
        ),
        LirTerminator::Call {
            target,
            return_target,
            does_return,
        } => {
            let mut extras = Vec::new();
            if let Some(value) = return_target {
                extras.push(format!("RET={}", render_expression(value)));
            }
            if let Some(value) = does_return {
                extras.push(format!("DOES_RETURN={value}"));
            }
            if extras.is_empty() {
                format!("NEXT: {}; Ijk_Call", render_expression(target))
            } else {
                format!(
                    "NEXT: {}; Ijk_Call ; {}",
                    render_expression(target),
                    extras.join(", ")
                )
            }
        }
        LirTerminator::Return { expression } => match expression {
            Some(value) => format!("NEXT: {}; Ijk_Ret", render_expression(value)),
            None => "NEXT: ret; Ijk_Ret".to_string(),
        },
        LirTerminator::Unreachable => "NEXT: unreachable; Ijk_NoDecode".to_string(),
        LirTerminator::Trap => "NEXT: trap; Ijk_SigTRAP".to_string(),
    }
}

fn render_location_read(location: &LirLocation) -> String {
    match location {
        LirLocation::Register { name, bits } => format!("GET({name}:{bits})"),
        LirLocation::Flag { name, bits } => format!("GET(flag:{name}:{bits})"),
        LirLocation::ProgramCounter { bits } => format!("GET(pc:{bits})"),
        LirLocation::Temporary { id, .. } => format!("t{id}"),
        LirLocation::Memory { space, addr, bits } => format!(
            "LD{}({}, {})",
            bits,
            render_address_space(space),
            render_expression(addr)
        ),
        LirLocation::IndexedMemory { name, index, bits } => {
            format!("LDIDX{}({}, {})", bits, name, render_expression(index))
        }
        LirLocation::StackMemory { name, offset, bits } => {
            format!("LDSTK{}({}, {})", bits, name, offset)
        }
    }
}

fn render_location_write(location: &LirLocation) -> String {
    match location {
        LirLocation::Register { name, .. } => format!("PUT({name})"),
        LirLocation::Flag { name, .. } => format!("PUT(flag:{name})"),
        LirLocation::ProgramCounter { .. } => "PUT(pc)".to_string(),
        LirLocation::Temporary { id, .. } => format!("t{id}"),
        LirLocation::Memory { space, addr, bits } => format!(
            "ST{}({}, {})",
            bits,
            render_address_space(space),
            render_expression(addr)
        ),
        LirLocation::IndexedMemory { name, index, bits } => {
            format!("STIDX{}({}, {})", bits, name, render_expression(index))
        }
        LirLocation::StackMemory { name, offset, bits } => {
            format!("STSTK{}({}, {})", bits, name, offset)
        }
    }
}

fn render_expression(expression: &LirExpression) -> String {
    match expression {
        LirExpression::Const { value, .. } => format!("0x{:x}", value),
        LirExpression::Function { name, .. } => format!("FN({name})"),
        LirExpression::DataAddress { name, .. } => format!("DATA({name})"),
        LirExpression::AddressOf { location, .. } => {
            format!("ADDR({})", render_location_read(location))
        }
        LirExpression::Read(location) => render_location_read(location),
        LirExpression::Load { space, addr, bits } => format!(
            "LD{}({}, {})",
            bits,
            render_address_space(space),
            render_expression(addr)
        ),
        LirExpression::Unary { op, arg, .. } => {
            format!("{}({})", render_unary_op(*op), render_expression(arg))
        }
        LirExpression::Binary {
            op, left, right, ..
        } => format!(
            "{}({}, {})",
            render_binary_op(*op),
            render_expression(left),
            render_expression(right)
        ),
        LirExpression::Cast { op, arg, bits } => format!(
            "{}({}, {})",
            render_cast_op(*op),
            render_expression(arg),
            bits
        ),
        LirExpression::Compare {
            op, left, right, ..
        } => format!(
            "{}({}, {})",
            render_compare_op(*op),
            render_expression(left),
            render_expression(right)
        ),
        LirExpression::Select {
            condition,
            when_true,
            when_false,
            ..
        } => format!(
            "ITE({}, {}, {})",
            render_expression(condition),
            render_expression(when_true),
            render_expression(when_false)
        ),
        LirExpression::Extract { arg, lsb, bits } => {
            format!("Extract({}, {}, {})", render_expression(arg), lsb, bits)
        }
        LirExpression::Concat { parts, .. } => format!(
            "Concat({})",
            parts
                .iter()
                .map(render_expression)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        LirExpression::Undefined { bits } => format!("Undefined({bits})"),
        LirExpression::Poison { bits } => format!("Poison({bits})"),
        LirExpression::Null { bits } => format!("Null({bits})"),
        LirExpression::Allocate { kind, bits } => format!("Allocate({kind}, {bits})"),
        LirExpression::ReadProperty {
            reference,
            name,
            bits,
        } => format!(
            "ReadProperty{}({}, {})",
            bits,
            render_expression(reference),
            name
        ),
        LirExpression::ReadElement {
            reference,
            index,
            bits,
        } => format!(
            "ReadElement{}({}, {})",
            bits,
            render_expression(reference),
            render_expression(index)
        ),
        LirExpression::Intrinsic { name, args, .. } => format!(
            "{}({})",
            name,
            args.iter()
                .map(render_expression)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn render_address_space(space: &LirAddressSpace) -> String {
    match space {
        LirAddressSpace::Default => "default".to_string(),
        LirAddressSpace::State => "state".to_string(),
        LirAddressSpace::Stack => "stack".to_string(),
        LirAddressSpace::Heap => "heap".to_string(),
        LirAddressSpace::Global => "global".to_string(),
        LirAddressSpace::Io => "io".to_string(),
        LirAddressSpace::CpuMemory { name } => format!("cpu:{name}"),
        LirAddressSpace::Segment { name } => format!("segment:{name}"),
        LirAddressSpace::Named { name } => format!("named:{name}"),
    }
}

fn render_unary_op(op: LirOperationUnary) -> &'static str {
    match op {
        LirOperationUnary::Not => "Not",
        LirOperationUnary::Neg => "Neg",
        LirOperationUnary::BitReverse => "BitReverse",
        LirOperationUnary::ByteSwap => "ByteSwap",
        LirOperationUnary::CountLeadingZeros => "Clz",
        LirOperationUnary::CountTrailingZeros => "Ctz",
        LirOperationUnary::PopCount => "PopCount",
        LirOperationUnary::Sqrt => "Sqrt",
        LirOperationUnary::Abs => "Abs",
    }
}

fn render_binary_op(op: LirOperationBinary) -> &'static str {
    match op {
        LirOperationBinary::Add => "Add",
        LirOperationBinary::AddWithCarry => "AddWithCarry",
        LirOperationBinary::Sub => "Sub",
        LirOperationBinary::SubWithBorrow => "SubWithBorrow",
        LirOperationBinary::Mul => "Mul",
        LirOperationBinary::FAdd => "FAdd",
        LirOperationBinary::FSub => "FSub",
        LirOperationBinary::FMul => "FMul",
        LirOperationBinary::FDiv => "FDiv",
        LirOperationBinary::UMulHigh => "UMulHigh",
        LirOperationBinary::SMulHigh => "SMulHigh",
        LirOperationBinary::UDiv => "UDiv",
        LirOperationBinary::SDiv => "SDiv",
        LirOperationBinary::URem => "URem",
        LirOperationBinary::SRem => "SRem",
        LirOperationBinary::And => "And",
        LirOperationBinary::Or => "Or",
        LirOperationBinary::Xor => "Xor",
        LirOperationBinary::Shl => "Shl",
        LirOperationBinary::LShr => "LShr",
        LirOperationBinary::AShr => "AShr",
        LirOperationBinary::RotateLeft => "Rol",
        LirOperationBinary::RotateRight => "Ror",
        LirOperationBinary::MinUnsigned => "MinU",
        LirOperationBinary::MinSigned => "MinS",
        LirOperationBinary::MaxUnsigned => "MaxU",
        LirOperationBinary::MaxSigned => "MaxS",
    }
}

fn render_cast_op(op: LirOperationCast) -> &'static str {
    match op {
        LirOperationCast::ZeroExtend => "ZeroExtend",
        LirOperationCast::SignExtend => "SignExtend",
        LirOperationCast::Truncate => "Truncate",
        LirOperationCast::Bitcast => "Bitcast",
        LirOperationCast::IntToFloat => "IntToFloat",
        LirOperationCast::UIntToFloat => "UIntToFloat",
        LirOperationCast::FloatToInt => "FloatToInt",
        LirOperationCast::FloatToUInt => "FloatToUInt",
        LirOperationCast::FloatExtend => "FloatExtend",
        LirOperationCast::FloatTruncate => "FloatTruncate",
    }
}

fn render_compare_op(op: LirOperationCompare) -> &'static str {
    match op {
        LirOperationCompare::Eq => "CmpEQ",
        LirOperationCompare::Ne => "CmpNE",
        LirOperationCompare::Ult => "CmpULT",
        LirOperationCompare::Ule => "CmpULE",
        LirOperationCompare::Ugt => "CmpUGT",
        LirOperationCompare::Uge => "CmpUGE",
        LirOperationCompare::Slt => "CmpSLT",
        LirOperationCompare::Sle => "CmpSLE",
        LirOperationCompare::Sgt => "CmpSGT",
        LirOperationCompare::Sge => "CmpSGE",
        LirOperationCompare::Ordered => "CmpORD",
        LirOperationCompare::Unordered => "CmpUNO",
        LirOperationCompare::Oeq => "CmpOEQ",
        LirOperationCompare::One => "CmpONE",
        LirOperationCompare::Olt => "CmpOLT",
        LirOperationCompare::Ole => "CmpOLE",
        LirOperationCompare::Ogt => "CmpOGT",
        LirOperationCompare::Oge => "CmpOGE",
        LirOperationCompare::Ueq => "CmpUEQ",
        LirOperationCompare::Une => "CmpUNE",
        LirOperationCompare::UltFp => "CmpULTFp",
        LirOperationCompare::UleFp => "CmpULEFp",
        LirOperationCompare::UgtFp => "CmpUGTFp",
        LirOperationCompare::UgeFp => "CmpUGEFp",
    }
}

#[cfg(test)]
mod tests {
    use super::{VexBlock, VexFunction, VexModule, VexStatement};

    #[test]
    fn structured_vex_text_keeps_header_and_body() {
        let mut module = VexModule::new(Some("module".to_string()));
        let mut function = VexFunction::new(Some("function_1000".to_string()));
        let mut block = VexBlock::new(Some("block_1000".to_string()));
        block.append_statement(VexStatement::new("   NEXT: ret; Ijk_Ret"));
        function.append_block(block);
        module.append_function(function);

        let rendered = module.text();
        assert!(rendered.contains("; function function_1000"));
        assert!(rendered.contains("; block block_1000"));
        assert!(rendered.contains("IRSB {"));
    }
}
