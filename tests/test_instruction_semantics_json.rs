use binlex::controlflow::Instruction;
use binlex::semantics::{
    InstructionSemantics, SemanticEffect, SemanticExpression, SemanticLocation, SemanticStatus,
    SemanticTerminator,
};
use binlex::{Architecture, Config};
use serde_json::to_value;
use std::collections::BTreeSet;

fn instruction_with_semantics(config: Config) -> Instruction {
    Instruction {
        architecture: Architecture::AMD64,
        config,
        address: 0x1000,
        is_prologue: false,
        is_block_start: false,
        is_function_start: false,
        bytes: vec![0x31, 0xC0],
        chromosome_mask: vec![0x00, 0x00],
        pattern: "31c0".to_string(),
        is_return: false,
        is_call: false,
        is_jump: false,
        is_conditional: false,
        is_trap: false,
        has_indirect_target: false,
        functions: BTreeSet::new(),
        to: BTreeSet::new(),
        edges: 0,
        mnemonic: String::new(),
        disassembly: String::new(),
        operands: Vec::new(),
        semantics: Some(InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "eax".to_string(),
                    bits: 32,
                },
                expression: SemanticExpression::Const { value: 0, bits: 32 },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        }),
    }
}

#[test]
fn instruction_json_includes_semantics_by_default() {
    let instruction = instruction_with_semantics(Config::default());
    let value = to_value(instruction.process()).expect("serialize instruction");
    assert!(value.get("semantics").is_some());
}

#[test]
fn instruction_json_omits_semantics_when_disabled_for_instruction_json() {
    let mut config = Config::default();
    config.instructions.semantics.enabled = false;
    let instruction = instruction_with_semantics(config);
    let value = to_value(instruction.process()).expect("serialize instruction");
    assert!(value.get("semantics").is_none());
}
