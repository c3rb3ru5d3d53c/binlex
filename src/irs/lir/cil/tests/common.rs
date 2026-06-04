use std::collections::BTreeMap;

use crate::controlflow::{Graph, InstructionRecord};
use crate::disassemblers::cil::Disassembler;
use crate::irs::lir::{Lir, LirStatus};
use crate::irs::llvm::LlvmModule;
use crate::{Architecture, Configuration};

pub(super) fn disassemble_cil_single(name: &str, bytes: &[u8]) -> InstructionRecord {
    let config = Configuration::default();
    let mut ranges = BTreeMap::new();
    ranges.insert(0, bytes.len() as u64);

    let mut graph = Graph::new(Architecture::CIL, config.clone());
    let disassembler =
        Disassembler::new(Architecture::CIL, bytes, ranges, config).expect("cil disassembler");
    disassembler
        .disassemble_instruction(0, &BTreeMap::new(), &mut graph)
        .unwrap_or_else(|error| panic!("{name}: instruction should disassemble: {error}"));
    graph
        .get_instruction_record(0)
        .expect("instruction should exist")
}

pub(super) fn semantics(name: &str, bytes: &[u8]) -> Lir {
    disassemble_cil_single(name, bytes)
        .build_semantics()
        .expect("instruction should build semantics")
}

pub(super) fn assert_complete_semantics(name: &str, bytes: &[u8]) -> Lir {
    let semantics = semantics(name, bytes);
    assert_eq!(
        semantics.status,
        LirStatus::Complete,
        "{name}: expected complete semantics, got {:?} with diagnostics {:?}",
        semantics.status,
        semantics
            .diagnostics
            .iter()
            .map(|diagnostic| diagnostic.message.clone())
            .collect::<Vec<_>>()
    );
    assert!(
        semantics.diagnostics.is_empty(),
        "{name}: expected no diagnostics, got {:?}",
        semantics
            .diagnostics
            .iter()
            .map(|diagnostic| diagnostic.message.clone())
            .collect::<Vec<_>>()
    );
    semantics
}

pub(super) fn lift_instruction_to_llvm(name: &str, bytes: &[u8]) -> String {
    let instruction = disassemble_cil_single(name, bytes);
    let mut graph = Graph::new(Architecture::CIL, Configuration::default());
    graph.insert_instruction(instruction);
    let instruction = graph.instruction(0).expect("instruction should exist");
    let mut lifter = LlvmModule::from_architecture(crate::Architecture::CIL);
    lifter
        .populate_instruction(&instruction)
        .unwrap_or_else(|error| panic!("{name}: instruction should lift: {error}"));
    lifter
        .verify()
        .unwrap_or_else(|error| panic!("{name}: llvm module should verify: {error}"));
    lifter.text()
}
