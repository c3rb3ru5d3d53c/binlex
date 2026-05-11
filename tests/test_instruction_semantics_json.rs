use binlex::controlflow::InstructionRecord;
use binlex::semantics::{
    Semantic, SemanticEffect, SemanticExpression, SemanticLocation, SemanticStatus,
    SemanticTerminator,
};
use binlex::{Architecture, Configuration};
use serde_json::to_value;

fn instruction_with_semantics(config: Configuration) -> InstructionRecord {
    let mut instruction = InstructionRecord::create(0x1000, Architecture::AMD64, config);
    instruction.bytes = vec![0x31, 0xC0];
    instruction.chromosome_mask = vec![0x00, 0x00];
    instruction.pattern = "31c0".to_string();
    instruction.semantics = Some(Semantic {
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
    });
    instruction
}

#[test]
fn instruction_json_includes_semantics_by_default() {
    let instruction = instruction_with_semantics(Configuration::default());
    let value = to_value(instruction.process_base()).expect("serialize instruction");
    assert!(value.get("semantics").is_some());
}

#[test]
fn instruction_json_omits_semantics_when_disabled_for_instruction_json() {
    let mut config = Configuration::default();
    config.instructions.semantics.enabled = false;
    let instruction = instruction_with_semantics(config);
    let value = to_value(instruction.process_base()).expect("serialize instruction");
    assert!(value.get("semantics").is_none());
}
