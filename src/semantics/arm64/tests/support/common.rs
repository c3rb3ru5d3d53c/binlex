use std::collections::BTreeMap;

use crate::controlflow::{Graph, InstructionRecord};
use crate::disassemblers::Disassembler;
use crate::lifters::llvm::Lifter;
use crate::semantics::{Semantic, SemanticStatus};
use crate::{Architecture, Configuration};

pub(crate) fn disassemble_arm64_single(name: &str, bytes: &[u8]) -> InstructionRecord {
    let config = Configuration::default();
    let mut ranges = BTreeMap::new();
    ranges.insert(0, bytes.len() as u64);

    let mut graph = Graph::new(Architecture::ARM64, config.clone());
    let disassembler =
        Disassembler::from_bytes(Architecture::ARM64, bytes, ranges, config).expect("disassembler");
    let metadata_token_addresses = BTreeMap::new();
    disassembler
        .disassemble_instruction(0, &metadata_token_addresses, &mut graph)
        .unwrap_or_else(|error| panic!("{name}: instruction should disassemble: {error}"));
    graph
        .get_instruction_record(0)
        .expect("instruction should exist")
}

pub(crate) fn semantics(name: &str, bytes: &[u8]) -> Semantic {
    disassemble_arm64_single(name, bytes)
        .semantics
        .expect("instruction should have semantics")
}

pub(crate) fn assert_semantics_status(
    name: &str,
    bytes: &[u8],
    expected_status: SemanticStatus,
) -> Semantic {
    let semantics = semantics(name, bytes);
    assert_eq!(
        semantics.status,
        expected_status,
        "{name}: expected {:?} semantics, got {:?} with diagnostics {:?}",
        expected_status,
        semantics.status,
        semantics
            .diagnostics
            .iter()
            .map(|diagnostic| diagnostic.message.clone())
            .collect::<Vec<_>>()
    );
    if expected_status == SemanticStatus::Complete {
        assert!(
            semantics.diagnostics.is_empty(),
            "{name}: expected no diagnostics, got {:?}",
            semantics
                .diagnostics
                .iter()
                .map(|diagnostic| diagnostic.message.clone())
                .collect::<Vec<_>>()
        );
    }
    semantics
}

pub(crate) fn lift_instruction_to_llvm(name: &str, bytes: &[u8]) -> String {
    let instruction = disassemble_arm64_single(name, bytes);
    let mut graph = Graph::new(Architecture::ARM64, Configuration::default());
    graph.insert_instruction(instruction);
    let instruction = graph.get_instruction(0).expect("instruction should exist");
    let mut lifter =
        Lifter::from_architecture(crate::Architecture::ARM64, Configuration::default());
    lifter
        .lift_instruction(&instruction)
        .unwrap_or_else(|error| panic!("{name}: instruction should lift: {error}"));
    lifter
        .verify()
        .unwrap_or_else(|error| panic!("{name}: llvm module should verify: {error}"));
    lifter.ir()
}
