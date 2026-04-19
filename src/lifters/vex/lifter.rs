use std::collections::BTreeMap;
use std::io::{Error, ErrorKind};

use serde::{Deserialize, Serialize};

use crate::Config;
use crate::controlflow::{Block, Function, Instruction};
use crate::core::Architecture;
use crate::semantics::{
    InstructionSemanticsJson, SemanticAddressSpace, SemanticDiagnostic, SemanticEffect,
    SemanticExpression, SemanticLocation, SemanticOperationBinary, SemanticOperationCast,
    SemanticOperationCompare, SemanticOperationUnary, SemanticTerminator,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct InstructionRequest {
    address: u64,
    bytes: Vec<u8>,
    semantics: InstructionSemanticsJson,
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

#[derive(Clone, Debug)]
struct Artifact {
    kind: ArtifactKind,
    name: String,
    architecture: Architecture,
    address: u64,
    text: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ArtifactKind {
    Instruction,
    Block,
    Function,
}

impl ArtifactKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Instruction => "instruction",
            Self::Block => "block",
            Self::Function => "function",
        }
    }
}

pub struct Lifter {
    _config: Config,
    artifacts: BTreeMap<String, Artifact>,
    rendered_override: Option<String>,
}

impl Lifter {
    pub fn new(config: Config) -> Self {
        Self {
            _config: config,
            artifacts: BTreeMap::new(),
            rendered_override: None,
        }
    }

    pub fn lift_instruction(&mut self, instruction: &Instruction) -> Result<(), Error> {
        self.ensure_enabled()?;
        self.ensure_supported_architecture(instruction.architecture)?;
        let name = format!("instruction_{:x}", instruction.address);
        if self.artifacts.contains_key(&name) {
            return Ok(());
        }
        let request = self.instruction_request(instruction)?;
        let text = self.execute(Request::Instruction {
            architecture: instruction.architecture,
            instruction: request,
        })?;
        self.rendered_override = None;
        self.artifacts.insert(
            name.clone(),
            Artifact {
                kind: ArtifactKind::Instruction,
                name,
                architecture: instruction.architecture,
                address: instruction.address,
                text,
            },
        );
        Ok(())
    }

    pub fn lift_block(&mut self, block: &Block<'_>) -> Result<(), Error> {
        self.ensure_enabled()?;
        let architecture = block.architecture();
        self.ensure_supported_architecture(architecture)?;
        let name = format!("block_{:x}", block.address());
        if self.artifacts.contains_key(&name) {
            return Ok(());
        }
        let request = self.block_request(block)?;
        let text = self.execute(Request::Block {
            architecture,
            block: request,
        })?;
        self.rendered_override = None;
        self.artifacts.insert(
            name.clone(),
            Artifact {
                kind: ArtifactKind::Block,
                name,
                architecture,
                address: block.address(),
                text,
            },
        );
        Ok(())
    }

    pub fn lift_function(&mut self, function: &Function<'_>) -> Result<(), Error> {
        self.ensure_enabled()?;
        let architecture = function.architecture();
        self.ensure_supported_architecture(architecture)?;
        let name = format!("function_{:x}", function.address());
        if self.artifacts.contains_key(&name) {
            return Ok(());
        }
        let blocks = function
            .blocks
            .values()
            .map(|block| self.block_request(block))
            .collect::<Result<Vec<_>, _>>()?;
        let text = self.execute(Request::Function {
            architecture,
            address: function.address(),
            blocks,
        })?;
        self.rendered_override = None;
        self.artifacts.insert(
            name.clone(),
            Artifact {
                kind: ArtifactKind::Function,
                name,
                architecture,
                address: function.address(),
                text,
            },
        );
        Ok(())
    }

    pub fn text(&self) -> String {
        self.rendered_override
            .clone()
            .unwrap_or_else(|| render_artifacts(self.artifacts.values()))
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

    fn ensure_enabled(&self) -> Result<(), Error> {
        if self._config.lifters.vex.enabled {
            return Ok(());
        }
        Err(Error::new(
            ErrorKind::PermissionDenied,
            "vex lifter is disabled in config",
        ))
    }

    fn execute(&self, request: Request) -> Result<String, Error> {
        Ok(match request {
            Request::Instruction { instruction, .. } => render_instruction_artifact(&instruction),
            Request::Block { block, .. } => render_block_artifact(&block),
            Request::Function {
                address, blocks, ..
            } => render_function_artifact(address, &blocks),
        })
    }

    fn instruction_request(&self, instruction: &Instruction) -> Result<InstructionRequest, Error> {
        Ok(InstructionRequest {
            address: instruction.address,
            bytes: instruction.bytes.clone(),
            semantics: instruction
                .semantics
                .as_ref()
                .ok_or_else(|| {
                    Error::new(
                        ErrorKind::InvalidInput,
                        format!(
                            "instruction 0x{:x} is missing semantics required for VEX lifting",
                            instruction.address
                        ),
                    )
                })?
                .process(),
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

fn render_function_artifact(address: u64, blocks: &[BlockRequest]) -> String {
    let mut lines = vec![format!("; function 0x{address:x}")];
    for block in blocks {
        lines.push(format!("; block 0x{:x}", block.address));
        lines.extend(render_block_body(block));
    }
    lines.join("\n")
}

fn render_block_artifact(block: &BlockRequest) -> String {
    render_block_body(block).join("\n")
}

fn render_block_body(block: &BlockRequest) -> Vec<String> {
    let mut lines = vec!["IRSB {".to_string()];
    for instruction in &block.instructions {
        lines.extend(render_instruction_body(instruction));
    }
    lines.push("}".to_string());
    lines
}

fn render_instruction_artifact(instruction: &InstructionRequest) -> String {
    let mut lines = vec!["IRSB {".to_string()];
    lines.extend(render_instruction_body(instruction));
    lines.push("}".to_string());
    lines.join("\n")
}

fn render_instruction_body(instruction: &InstructionRequest) -> Vec<String> {
    let mut lines = vec![format!(
        "   ------ IMark(0x{:016x}, {}, 0) ------",
        instruction.address,
        instruction.bytes.len()
    )];

    for temp in &instruction.semantics.temporaries {
        let name = temp
            .name
            .as_deref()
            .map(|value| format!(" ; {}", value))
            .unwrap_or_default();
        lines.push(format!("   t{}:{}{}", temp.id, temp.bits, name));
    }

    for effect in &instruction.semantics.effects {
        lines.push(format!("   {}", render_effect(effect)));
    }

    for diagnostic in &instruction.semantics.diagnostics {
        lines.push(format!("   ; diag {}", render_diagnostic(diagnostic)));
    }

    lines.push(format!(
        "   {}",
        render_terminator(&instruction.semantics.terminator)
    ));
    lines
}

fn render_diagnostic(diagnostic: &SemanticDiagnostic) -> String {
    format!("{:?}: {}", diagnostic.kind, diagnostic.message)
}

fn render_effect(effect: &SemanticEffect) -> String {
    match effect {
        SemanticEffect::Set { dst, expression } => {
            format!(
                "{} = {}",
                render_location_write(dst),
                render_expression(expression)
            )
        }
        SemanticEffect::Store {
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
        SemanticEffect::Fence { kind } => format!("DIRTY fence({kind:?})"),
        SemanticEffect::Trap { kind } => format!("DIRTY trap({kind:?})"),
        SemanticEffect::Intrinsic {
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
        SemanticEffect::Nop => "NOP".to_string(),
    }
}

fn render_terminator(terminator: &SemanticTerminator) -> String {
    match terminator {
        SemanticTerminator::FallThrough => "NEXT: fallthrough; Ijk_Boring".to_string(),
        SemanticTerminator::Jump { target } => {
            format!("NEXT: {}; Ijk_Boring", render_expression(target))
        }
        SemanticTerminator::Branch {
            condition,
            true_target,
            false_target,
        } => format!(
            "if ({}) {{ NEXT: {} }} else {{ NEXT: {} }}; Ijk_Boring",
            render_expression(condition),
            render_expression(true_target),
            render_expression(false_target)
        ),
        SemanticTerminator::Call {
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
        SemanticTerminator::Return { expression } => match expression {
            Some(value) => format!("NEXT: {}; Ijk_Ret", render_expression(value)),
            None => "NEXT: ret; Ijk_Ret".to_string(),
        },
        SemanticTerminator::Unreachable => "NEXT: unreachable; Ijk_NoDecode".to_string(),
        SemanticTerminator::Trap => "NEXT: trap; Ijk_SigTRAP".to_string(),
    }
}

fn render_location_read(location: &SemanticLocation) -> String {
    match location {
        SemanticLocation::Register { name, bits } => format!("GET({name}:{bits})"),
        SemanticLocation::Flag { name, bits } => format!("GET(flag:{name}:{bits})"),
        SemanticLocation::ProgramCounter { bits } => format!("GET(pc:{bits})"),
        SemanticLocation::Temporary { id, .. } => format!("t{id}"),
        SemanticLocation::Memory { space, addr, bits } => format!(
            "LD{}({}, {})",
            bits,
            render_address_space(space),
            render_expression(addr)
        ),
    }
}

fn render_location_write(location: &SemanticLocation) -> String {
    match location {
        SemanticLocation::Register { name, .. } => format!("PUT({name})"),
        SemanticLocation::Flag { name, .. } => format!("PUT(flag:{name})"),
        SemanticLocation::ProgramCounter { .. } => "PUT(pc)".to_string(),
        SemanticLocation::Temporary { id, .. } => format!("t{id}"),
        SemanticLocation::Memory { space, addr, bits } => format!(
            "ST{}({}, {})",
            bits,
            render_address_space(space),
            render_expression(addr)
        ),
    }
}

fn render_expression(expression: &SemanticExpression) -> String {
    match expression {
        SemanticExpression::Const { value, .. } => format!("0x{:x}", value),
        SemanticExpression::Read(location) => render_location_read(location),
        SemanticExpression::Load { space, addr, bits } => format!(
            "LD{}({}, {})",
            bits,
            render_address_space(space),
            render_expression(addr)
        ),
        SemanticExpression::Unary { op, arg, .. } => {
            format!("{}({})", render_unary_op(*op), render_expression(arg))
        }
        SemanticExpression::Binary {
            op, left, right, ..
        } => format!(
            "{}({}, {})",
            render_binary_op(*op),
            render_expression(left),
            render_expression(right)
        ),
        SemanticExpression::Cast { op, arg, bits } => format!(
            "{}({}, {})",
            render_cast_op(*op),
            render_expression(arg),
            bits
        ),
        SemanticExpression::Compare {
            op, left, right, ..
        } => format!(
            "{}({}, {})",
            render_compare_op(*op),
            render_expression(left),
            render_expression(right)
        ),
        SemanticExpression::Select {
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
        SemanticExpression::Extract { arg, lsb, bits } => {
            format!("Extract({}, {}, {})", render_expression(arg), lsb, bits)
        }
        SemanticExpression::Concat { parts, .. } => format!(
            "Concat({})",
            parts
                .iter()
                .map(render_expression)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        SemanticExpression::Undefined { bits } => format!("Undefined({bits})"),
        SemanticExpression::Poison { bits } => format!("Poison({bits})"),
        SemanticExpression::Intrinsic { name, args, .. } => format!(
            "{}({})",
            name,
            args.iter()
                .map(render_expression)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn render_address_space(space: &SemanticAddressSpace) -> String {
    match space {
        SemanticAddressSpace::Default => "default".to_string(),
        SemanticAddressSpace::Stack => "stack".to_string(),
        SemanticAddressSpace::Heap => "heap".to_string(),
        SemanticAddressSpace::Global => "global".to_string(),
        SemanticAddressSpace::Io => "io".to_string(),
        SemanticAddressSpace::Segment { name } => format!("segment:{name}"),
        SemanticAddressSpace::ArchSpecific { name } => format!("arch:{name}"),
    }
}

fn render_unary_op(op: SemanticOperationUnary) -> &'static str {
    match op {
        SemanticOperationUnary::Not => "Not",
        SemanticOperationUnary::Neg => "Neg",
        SemanticOperationUnary::BitReverse => "BitReverse",
        SemanticOperationUnary::ByteSwap => "ByteSwap",
        SemanticOperationUnary::CountLeadingZeros => "Clz",
        SemanticOperationUnary::CountTrailingZeros => "Ctz",
        SemanticOperationUnary::PopCount => "PopCount",
        SemanticOperationUnary::Sqrt => "Sqrt",
        SemanticOperationUnary::Abs => "Abs",
    }
}

fn render_binary_op(op: SemanticOperationBinary) -> &'static str {
    match op {
        SemanticOperationBinary::Add => "Add",
        SemanticOperationBinary::AddWithCarry => "AddWithCarry",
        SemanticOperationBinary::Sub => "Sub",
        SemanticOperationBinary::SubWithBorrow => "SubWithBorrow",
        SemanticOperationBinary::Mul => "Mul",
        SemanticOperationBinary::UMulHigh => "UMulHigh",
        SemanticOperationBinary::SMulHigh => "SMulHigh",
        SemanticOperationBinary::UDiv => "UDiv",
        SemanticOperationBinary::SDiv => "SDiv",
        SemanticOperationBinary::URem => "URem",
        SemanticOperationBinary::SRem => "SRem",
        SemanticOperationBinary::And => "And",
        SemanticOperationBinary::Or => "Or",
        SemanticOperationBinary::Xor => "Xor",
        SemanticOperationBinary::Shl => "Shl",
        SemanticOperationBinary::LShr => "LShr",
        SemanticOperationBinary::AShr => "AShr",
        SemanticOperationBinary::RotateLeft => "Rol",
        SemanticOperationBinary::RotateRight => "Ror",
        SemanticOperationBinary::MinUnsigned => "MinU",
        SemanticOperationBinary::MinSigned => "MinS",
        SemanticOperationBinary::MaxUnsigned => "MaxU",
        SemanticOperationBinary::MaxSigned => "MaxS",
    }
}

fn render_cast_op(op: SemanticOperationCast) -> &'static str {
    match op {
        SemanticOperationCast::ZeroExtend => "ZeroExtend",
        SemanticOperationCast::SignExtend => "SignExtend",
        SemanticOperationCast::Truncate => "Truncate",
        SemanticOperationCast::Bitcast => "Bitcast",
        SemanticOperationCast::IntToFloat => "IntToFloat",
        SemanticOperationCast::FloatToInt => "FloatToInt",
        SemanticOperationCast::FloatExtend => "FloatExtend",
        SemanticOperationCast::FloatTruncate => "FloatTruncate",
    }
}

fn render_compare_op(op: SemanticOperationCompare) -> &'static str {
    match op {
        SemanticOperationCompare::Eq => "CmpEQ",
        SemanticOperationCompare::Ne => "CmpNE",
        SemanticOperationCompare::Ult => "CmpULT",
        SemanticOperationCompare::Ule => "CmpULE",
        SemanticOperationCompare::Ugt => "CmpUGT",
        SemanticOperationCompare::Uge => "CmpUGE",
        SemanticOperationCompare::Slt => "CmpSLT",
        SemanticOperationCompare::Sle => "CmpSLE",
        SemanticOperationCompare::Sgt => "CmpSGT",
        SemanticOperationCompare::Sge => "CmpSGE",
        SemanticOperationCompare::Ordered => "CmpORD",
        SemanticOperationCompare::Unordered => "CmpUNO",
        SemanticOperationCompare::Oeq => "CmpOEQ",
        SemanticOperationCompare::One => "CmpONE",
        SemanticOperationCompare::Olt => "CmpOLT",
        SemanticOperationCompare::Ole => "CmpOLE",
        SemanticOperationCompare::Ogt => "CmpOGT",
        SemanticOperationCompare::Oge => "CmpOGE",
        SemanticOperationCompare::Ueq => "CmpUEQ",
        SemanticOperationCompare::Une => "CmpUNE",
        SemanticOperationCompare::UltFp => "CmpULTFp",
        SemanticOperationCompare::UleFp => "CmpULEFp",
        SemanticOperationCompare::UgtFp => "CmpUGTFp",
        SemanticOperationCompare::UgeFp => "CmpUGEFp",
    }
}

fn render_artifacts<'a>(artifacts: impl IntoIterator<Item = &'a Artifact>) -> String {
    let mut rendered = Vec::new();
    for artifact in artifacts {
        rendered.push(format!(
            "; {} {} {} 0x{:x}",
            artifact.kind.as_str(),
            artifact.name,
            artifact.architecture,
            artifact.address
        ));
        rendered.push(artifact.text.clone());
    }
    rendered.join("\n\n")
}

#[cfg(test)]
mod tests {
    use super::render_artifacts;
    use super::{Artifact, ArtifactKind};
    use crate::core::Architecture;

    #[test]
    fn render_artifacts_keeps_header_and_body() {
        let artifact = Artifact {
            kind: ArtifactKind::Function,
            name: "function_1000".to_string(),
            architecture: Architecture::AMD64,
            address: 0x1000,
            text: "IRSB {\n   NEXT: ret; Ijk_Ret\n}".to_string(),
        };
        let rendered = render_artifacts([&artifact]);
        assert!(rendered.contains("; function function_1000 amd64 0x1000"));
        assert!(rendered.contains("IRSB {"));
    }
}
