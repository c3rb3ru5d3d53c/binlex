use super::*;

pub fn partial(
    terminator: SemanticTerminator,
    diagnostics: Vec<SemanticDiagnostic>,
) -> InstructionSemantics {
    InstructionSemantics {
        version: 1,
        status: SemanticStatus::Partial,
        abi: None,
        encoding: None,
        temporaries: Vec::new(),
        effects: Vec::new(),
        terminator,
        diagnostics,
    }
}

pub fn complete(
    terminator: SemanticTerminator,
    effects: Vec<SemanticEffect>,
) -> InstructionSemantics {
    InstructionSemantics {
        version: 1,
        status: SemanticStatus::Complete,
        abi: None,
        encoding: None,
        temporaries: Vec::new(),
        effects,
        terminator,
        diagnostics: Vec::new(),
    }
}

pub fn partial_with_effects(
    terminator: SemanticTerminator,
    diagnostics: Vec<SemanticDiagnostic>,
    effects: Vec<SemanticEffect>,
) -> InstructionSemantics {
    InstructionSemantics {
        version: 1,
        status: SemanticStatus::Partial,
        abi: None,
        encoding: None,
        temporaries: Vec::new(),
        effects,
        terminator,
        diagnostics,
    }
}

pub fn partial_intrinsic_fallback(
    instruction: &Insn,
    terminator: SemanticTerminator,
    effects: Vec<SemanticEffect>,
) -> InstructionSemantics {
    partial_with_effects(
        terminator,
        vec![diagnostic(
            SemanticDiagnosticKind::ArchSpecific {
                name: "x86.intrinsic_fallback".to_string(),
            },
            format!(
                "0x{:x}: semantics use x86 intrinsic fallback ({})",
                instruction.address(),
                instruction.mnemonic().unwrap_or("unknown")
            ),
        )],
        effects,
    )
}

pub fn diagnostic(kind: SemanticDiagnosticKind, message: impl Into<String>) -> SemanticDiagnostic {
    SemanticDiagnostic {
        kind,
        message: message.into(),
    }
}

pub fn unsupported_fallthrough(instruction: &Insn, message: &str) -> InstructionSemantics {
    partial(
        SemanticTerminator::FallThrough,
        vec![diagnostic(
            SemanticDiagnosticKind::UnsupportedInstruction,
            format!(
                "0x{:x}: {} ({})",
                instruction.address(),
                message,
                instruction.mnemonic().unwrap_or("unknown")
            ),
        )],
    )
}

pub fn unsupported_with_kind(
    instruction: &Insn,
    kind: SemanticDiagnosticKind,
    message: &str,
    terminator: SemanticTerminator,
) -> InstructionSemantics {
    partial(
        terminator,
        vec![diagnostic(
            kind,
            format!(
                "0x{:x}: {} ({})",
                instruction.address(),
                message,
                instruction.mnemonic().unwrap_or("unknown")
            ),
        )],
    )
}
