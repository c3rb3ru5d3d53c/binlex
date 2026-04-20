use std::collections::BTreeMap;

use crate::controlflow::{Graph, Instruction};
use crate::disassemblers::cil::Disassembler;
use crate::lifters::llvm::Lifter;
use crate::semantics::{InstructionSemantics, SemanticStatus};
use crate::{Architecture, Config};

pub(super) fn disassemble_cil_single(name: &str, bytes: &[u8]) -> Instruction {
    let config = Config::default();
    let mut ranges = BTreeMap::new();
    ranges.insert(0, bytes.len() as u64);

    let mut graph = Graph::new(Architecture::CIL, config.clone());
    let disassembler = Disassembler::new(Architecture::CIL, bytes, BTreeMap::new(), ranges, config)
        .expect("cil disassembler");
    disassembler
        .disassemble_instruction(0, &mut graph)
        .unwrap_or_else(|error| panic!("{name}: instruction should disassemble: {error}"));
    graph.get_instruction(0).expect("instruction should exist")
}

pub(super) fn semantics(name: &str, bytes: &[u8]) -> InstructionSemantics {
    disassemble_cil_single(name, bytes)
        .semantics
        .expect("instruction should have semantics")
}

pub(super) fn assert_complete_semantics(name: &str, bytes: &[u8]) -> InstructionSemantics {
    let semantics = semantics(name, bytes);
    assert_eq!(
        semantics.status,
        SemanticStatus::Complete,
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
    let mut lifter = Lifter::new(Config::default());
    lifter
        .lift_instruction(&instruction)
        .unwrap_or_else(|error| panic!("{name}: instruction should lift: {error}"));
    lifter
        .verify()
        .unwrap_or_else(|error| panic!("{name}: llvm module should verify: {error}"));
    lifter.text()
}
