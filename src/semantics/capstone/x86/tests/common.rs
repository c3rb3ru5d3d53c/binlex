use std::collections::BTreeMap;

use crate::controlflow::{Graph, Instruction};
use crate::disassemblers::capstone::Disassembler;
use crate::semantics::{InstructionSemantics, SemanticStatus};
use crate::{Architecture, Config};

pub(super) fn disassemble_x86_single(
    name: &str,
    architecture: Architecture,
    bytes: &[u8],
) -> Instruction {
    let config = Config::default();
    let mut ranges = BTreeMap::new();
    ranges.insert(0, bytes.len() as u64);

    let mut graph = Graph::new(architecture, config.clone());
    let disassembler =
        Disassembler::from_bytes(architecture, bytes, ranges, config).expect("disassembler");
    disassembler
        .disassemble_instruction(0, &mut graph)
        .unwrap_or_else(|error| panic!("{name}: instruction should disassemble: {error}"));
    graph.get_instruction(0).expect("instruction should exist")
}

pub(super) fn semantics(
    name: &str,
    architecture: Architecture,
    bytes: &[u8],
) -> InstructionSemantics {
    disassemble_x86_single(name, architecture, bytes)
        .semantics
        .expect("instruction should have semantics")
}

pub(super) fn assert_complete_semantics(name: &str, architecture: Architecture, bytes: &[u8]) {
    let semantics = semantics(name, architecture, bytes);
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
}
