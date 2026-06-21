use std::collections::BTreeMap;

use crate::controlflow::{Graph, InstructionRecord};
use crate::disassemblers::cil::Disassembler;
use crate::irs::lir::{LirInstruction, LirStatus};
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

pub(super) fn lir(name: &str, bytes: &[u8]) -> LirInstruction {
    disassemble_cil_single(name, bytes)
        .build_lir()
        .expect("instruction should build lir")
}

pub(super) fn assert_complete_lir(name: &str, bytes: &[u8]) -> LirInstruction {
    let lir = lir(name, bytes);
    assert_eq!(
        lir.status,
        LirStatus::Complete,
        "{name}: expected complete lir, got {:?}",
        lir.status
    );
    lir
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
