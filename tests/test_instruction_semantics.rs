use std::collections::BTreeMap;

use binlex::controlflow::{Graph, Instruction};
use binlex::semantics::{
    InstructionSemantics, SemanticDiagnostic, SemanticDiagnosticKind, SemanticStatus,
    SemanticTerminator,
};
use binlex::{Architecture, Config};

fn disassemble_single(
    name: &str,
    architecture: Architecture,
    bytes: &[u8],
) -> binlex::controlflow::Instruction {
    let config = Config::default();
    let mut ranges = BTreeMap::new();
    ranges.insert(0, bytes.len() as u64);

    let mut graph = Graph::new(architecture, config.clone());

    match architecture {
        Architecture::CIL => {
            let disassembler = binlex::disassemblers::cil::Disassembler::new(
                architecture,
                bytes,
                BTreeMap::new(),
                ranges,
                config,
            )
            .expect("disassembler");
            disassembler
                .disassemble_instruction(0, &mut graph)
                .unwrap_or_else(|error| panic!("{name}: instruction should disassemble: {error}"));
        }
        _ => {
            let disassembler = binlex::disassemblers::capstone::Disassembler::from_bytes(
                architecture,
                bytes,
                ranges,
                config,
            )
            .expect("disassembler");
            disassembler
                .disassemble_instruction(0, &mut graph)
                .unwrap_or_else(|error| panic!("{name}: instruction should disassemble: {error}"));
        }
    }

    graph.get_instruction(0).expect("instruction should exist")
}

fn assert_partial_semantics(name: &str, architecture: Architecture, bytes: &[u8]) {
    let instruction = disassemble_single(name, architecture, bytes);
    let semantics = instruction
        .semantics
        .as_ref()
        .unwrap_or_else(|| panic!("{name}: missing semantics"));

    assert_eq!(
        semantics.status,
        SemanticStatus::Partial,
        "{name}: expected partial semantics, got {:?}",
        semantics.status
    );
    assert!(
        !semantics.diagnostics.is_empty(),
        "{name}: expected diagnostics for partial semantics"
    );
}

fn partial_semantics(message: &str) -> InstructionSemantics {
    InstructionSemantics {
        version: 1,
        status: SemanticStatus::Partial,
        temporaries: Vec::new(),
        effects: Vec::new(),
        terminator: SemanticTerminator::FallThrough,
        diagnostics: vec![SemanticDiagnostic {
            kind: SemanticDiagnosticKind::ArchSpecific {
                name: "test.partial".to_string(),
            },
            message: message.to_string(),
        }],
    }
}

fn complete_semantics() -> InstructionSemantics {
    InstructionSemantics {
        version: 1,
        status: SemanticStatus::Complete,
        temporaries: Vec::new(),
        effects: Vec::new(),
        terminator: SemanticTerminator::FallThrough,
        diagnostics: Vec::new(),
    }
}

#[test]
fn accuracy_gated_semantics_regressions_stay_partial() {
    let cases: [(&str, Architecture, Vec<u8>); 0] = [];

    for (name, architecture, bytes) in cases {
        assert_partial_semantics(name, architecture, &bytes);
    }
}

#[test]
fn instruction_semantics_survive_snapshot_roundtrip() {
    let instruction = disassemble_single("adc eax, ebx", Architecture::I386, &[0x11, 0xd8]);
    let original = instruction
        .semantics
        .clone()
        .expect("instruction should carry semantics");

    let config = Config::default();
    let mut graph = Graph::new(Architecture::I386, config.clone());
    graph.insert_instruction(instruction);

    let restored =
        Graph::from_snapshot(graph.snapshot(), config).expect("snapshot roundtrip should restore");
    let restored_instruction = restored
        .get_instruction(0)
        .expect("restored instruction should exist");
    let restored_semantics = restored_instruction
        .semantics
        .expect("restored instruction should keep semantics");

    assert_eq!(restored_semantics.status, original.status);
    assert_eq!(
        restored_semantics.terminator.kind(),
        original.terminator.kind()
    );
    assert_eq!(restored_semantics.effects.len(), original.effects.len());
    assert_eq!(
        restored_semantics.diagnostics.len(),
        original.diagnostics.len()
    );
}

#[test]
fn graph_merge_prefers_more_complete_instruction_semantics() {
    let config = Config::default();
    let mut base = Graph::new(Architecture::AMD64, config.clone());
    let mut incoming = Graph::new(Architecture::AMD64, config.clone());

    let mut partial_instruction = Instruction::create(0x1000, Architecture::AMD64, config.clone());
    partial_instruction.bytes = vec![0x90];
    partial_instruction.pattern = "90".to_string();
    partial_instruction.semantics = Some(partial_semantics("partial semantics"));
    base.insert_instruction(partial_instruction);

    let mut complete_instruction = Instruction::create(0x1000, Architecture::AMD64, config);
    complete_instruction.bytes = vec![0x90];
    complete_instruction.pattern = "90".to_string();
    complete_instruction.semantics = Some(complete_semantics());
    incoming.insert_instruction(complete_instruction);

    base.merge(&mut incoming);

    let merged = base
        .get_instruction(0x1000)
        .expect("merged instruction should exist")
        .semantics
        .expect("merged instruction should keep semantics");

    assert_eq!(merged.status, SemanticStatus::Complete);
    assert!(merged.diagnostics.is_empty());
}

#[test]
fn graph_update_instruction_preserves_attached_semantics() {
    let config = Config::default();
    let mut graph = Graph::new(Architecture::I386, config.clone());
    let mut instruction =
        disassemble_single("btc eax, 1", Architecture::I386, &[0x0f, 0xba, 0xf8, 0x01]);
    let original = instruction
        .semantics
        .clone()
        .expect("instruction should have semantics");

    graph.insert_instruction(instruction.clone());
    instruction.pattern = "0f baf8 01".replace(' ', "");
    graph.update_instruction(instruction);

    let updated = graph
        .get_instruction(0)
        .expect("updated instruction should exist")
        .semantics
        .expect("updated instruction should retain semantics");

    assert_eq!(updated.status, original.status);
    assert_eq!(updated.effects.len(), original.effects.len());
    assert_eq!(updated.terminator.kind(), original.terminator.kind());
}
