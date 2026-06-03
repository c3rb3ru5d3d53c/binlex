use binlex::controlflow::InstructionRecord;
use binlex::controlflow::{Function, Graph};
use binlex::disassemblers::x86::Disassembler;
use binlex::ir::lir::{
    LirEffect, LirExpression, LirInstruction, LirLocation, LirMetadata, LirStatus, LirTerminator,
};
use binlex::{Architecture, Configuration};
use serde_json::to_value;
use std::collections::BTreeMap;

fn instruction_with_semantics(config: Configuration) -> InstructionRecord {
    let mut instruction = InstructionRecord::create(0x1000, Architecture::AMD64, config);
    instruction.bytes = vec![0x31, 0xC0];
    instruction.chromosome_mask = vec![0x00, 0x00];
    instruction.pattern = "31c0".to_string();
    instruction.semantics = Some(LirInstruction {
        version: 1,
        status: LirStatus::Complete,
        metadata: LirMetadata::default(),
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
fn disassembly_leaves_lir_unpopulated_but_available_on_demand() {
    let bytes = vec![0x31, 0xc0, 0xc3];
    let mut ranges = BTreeMap::new();
    ranges.insert(0u64, bytes.len() as u64);
    let config = Configuration::default();
    let disasm =
        Disassembler::new(Architecture::AMD64, &bytes, ranges, config.clone()).expect("disasm");
    let mut graph = Graph::new(Architecture::AMD64, config);

    disasm
        .disassemble_function(0, &mut graph)
        .expect("disassemble");

    let instruction = graph.get_instruction(0).expect("instruction");
    assert!(instruction.semantics.is_none());
    assert!(instruction.build_semantics().is_some());

    let function = Function::new(0, &graph).expect("function");
    assert!(function.lir().is_ok());
}

#[test]
fn fallthrough_instruction_without_detail_still_builds_partial_lir() {
    let config = Configuration::default();
    let mut instruction = InstructionRecord::create(0x1000, Architecture::AMD64, config);
    instruction.bytes = vec![0x90];
    instruction.chromosome_mask = vec![0x00];
    instruction.pattern = "90".to_string();
    instruction.mnemonic = "nop".to_string();
    instruction.disassembly = "nop".to_string();

    let lir = instruction
        .build_semantics()
        .expect("fallthrough fallback lir");
    assert_eq!(lir.status, LirStatus::Partial);
    assert!(matches!(lir.terminator, LirTerminator::FallThrough));
    assert!(lir.effects.is_empty());
    assert_eq!(lir.encoding.expect("encoding").mnemonic, "nop");
}
