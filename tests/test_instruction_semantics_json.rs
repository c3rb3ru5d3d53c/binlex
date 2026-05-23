use binlex::controlflow::InstructionRecord;
use binlex::ir::lir::{
    LirEffect, LirExpression, LirInstruction, LirLocation, LirStatus, LirTerminator,
};
use binlex::{Architecture, Configuration};
use serde_json::to_value;

fn instruction_with_semantics(config: Configuration) -> InstructionRecord {
    let mut instruction = InstructionRecord::create(0x1000, Architecture::AMD64, config);
    instruction.bytes = vec![0x31, 0xC0];
    instruction.chromosome_mask = vec![0x00, 0x00];
    instruction.pattern = "31c0".to_string();
    instruction.semantics = Some(LirInstruction {
        version: 1,
        status: LirStatus::Complete,
        abi: None,
        encoding: None,
        temporaries: Vec::new(),
        effects: vec![LirEffect::Set {
            dst: LirLocation::Register {
                name: "eax".to_string(),
                bits: 32,
            },
            expression: LirExpression::Const { value: 0, bits: 32 },
        }],
        terminator: LirTerminator::FallThrough,
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
