use std::collections::BTreeMap;

use crate::controlflow::{Graph, InstructionRecord};
use crate::disassemblers::Disassembler;
use crate::irs::lir::{Lir, LirStatus};
use crate::irs::llvm::LlvmModule;
use crate::{Architecture, Configuration};

pub(crate) fn disassemble_arm64_single(name: &str, bytes: &[u8]) -> InstructionRecord {
    let config = Configuration::default();
    let mut ranges = BTreeMap::new();
    ranges.insert(0, bytes.len() as u64);

    let mut graph = Graph::new(Architecture::ARM64, config.clone());
    let disassembler =
        Disassembler::from_bytes(Architecture::ARM64, bytes, ranges, config).expect("disassembler");
    disassembler
        .disassemble_instruction(0, &mut graph)
        .unwrap_or_else(|error| panic!("{name}: instruction should disassemble: {error}"));
    graph
        .get_instruction_record(0)
        .expect("instruction should exist")
}

pub(crate) fn lir(name: &str, bytes: &[u8]) -> Lir {
    disassemble_arm64_single(name, bytes)
        .build_lir()
        .expect("instruction should build lir")
}

pub(crate) fn assert_lir_status(name: &str, bytes: &[u8], expected_status: LirStatus) -> Lir {
    let lir = lir(name, bytes);
    assert_eq!(
        lir.status,
        expected_status,
        "{name}: expected {:?} lir, got {:?} with diagnostics {:?}",
        expected_status,
        lir.status,
        lir.diagnostics
            .iter()
            .map(|diagnostic| diagnostic.message.clone())
            .collect::<Vec<_>>()
    );
    if expected_status == LirStatus::Complete {
        assert!(
            lir.diagnostics.is_empty(),
            "{name}: expected no diagnostics, got {:?}",
            lir.diagnostics
                .iter()
                .map(|diagnostic| diagnostic.message.clone())
                .collect::<Vec<_>>()
        );
    }
    lir
}

pub(crate) fn lift_instruction_to_llvm(name: &str, bytes: &[u8]) -> String {
    let instruction = disassemble_arm64_single(name, bytes);
    let mut graph = Graph::new(Architecture::ARM64, Configuration::default());
    graph.insert_instruction(instruction);
    let instruction = graph.instruction(0).expect("instruction should exist");
    let mut lifter = LlvmModule::from_architecture(crate::Architecture::ARM64);
    lifter
        .populate_instruction(&instruction)
        .unwrap_or_else(|error| panic!("{name}: instruction should lift: {error}"));
    lifter
        .verify()
        .unwrap_or_else(|error| panic!("{name}: llvm module should verify: {error}"));
    lifter.text()
}
