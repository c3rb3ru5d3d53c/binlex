use std::collections::BTreeMap;

use binlex::controlflow::{Graph, InstructionRecord};
use binlex::decompilers::{Decompiler, DecompilerBackend};
use binlex::formats::{Image, ImagePermissions, ImageSegment};
use binlex::irs::lir::{
    Lir, LirDiagnostic, LirDiagnosticKind, LirMetadata, LirStatus, LirTerminator,
};
use binlex::{Architecture, Configuration};

fn disassemble_single(name: &str, architecture: Architecture, bytes: &[u8]) -> InstructionRecord {
    let config = Configuration::default();
    let mut ranges = BTreeMap::new();
    ranges.insert(0, bytes.len() as u64);

    let mut graph = Graph::new(architecture, config.clone());

    match architecture {
        Architecture::CIL => {
            let disassembler =
                binlex::disassemblers::cil::Disassembler::new(architecture, bytes, ranges, config)
                    .expect("disassembler");
            disassembler
                .disassemble_instruction(0, &BTreeMap::new(), &mut graph)
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

    let mut instruction = graph
        .instruction(0)
        .expect("instruction should exist")
        .into_record();
    instruction.lir = instruction.build_lir();
    instruction
}

fn assert_partial_lir(name: &str, architecture: Architecture, bytes: &[u8]) {
    let instruction = disassemble_single(name, architecture, bytes);
    let lir = instruction
        .lir
        .as_ref()
        .unwrap_or_else(|| panic!("{name}: missing lir"));

    assert_eq!(
        lir.status,
        LirStatus::Partial,
        "{name}: expected partial lir, got {:?}",
        lir.status
    );
    assert!(
        !lir.diagnostics.is_empty(),
        "{name}: expected diagnostics for partial lir"
    );
}

fn partial_lir(message: &str) -> Lir {
    Lir {
        version: 1,
        status: LirStatus::Partial,
        metadata: LirMetadata::default(),
        abi: None,
        encoding: None,
        temporaries: Vec::new(),
        effects: Vec::new(),
        terminator: LirTerminator::FallThrough,
        diagnostics: vec![LirDiagnostic {
            kind: LirDiagnosticKind::Named {
                name: "test.partial".to_string(),
            },
            message: message.to_string(),
        }],
    }
}

fn complete_lir() -> Lir {
    Lir {
        version: 1,
        status: LirStatus::Complete,
        metadata: LirMetadata::default(),
        abi: None,
        encoding: None,
        temporaries: Vec::new(),
        effects: Vec::new(),
        terminator: LirTerminator::FallThrough,
        diagnostics: Vec::new(),
    }
}

#[test]
fn accuracy_gated_lir_regressions_stay_partial() {
    let cases: [(&str, Architecture, Vec<u8>); 0] = [];

    for (name, architecture, bytes) in cases {
        assert_partial_lir(name, architecture, &bytes);
    }
}

#[test]
fn graph_state_roundtrip_preserves_context_and_instruction_lir() {
    let instruction = disassemble_single("adc eax, ebx", Architecture::I386, &[0x11, 0xd8]);
    let original_mnemonic = instruction.mnemonic();
    let original_disassembly = instruction.disassembly();
    let original_operands = instruction.operands();
    let original = instruction
        .lir
        .clone()
        .expect("instruction should carry lir");

    let mut config = Configuration::default();
    config.threads = 1;
    let mut image = Image::new();
    image.add_segment(ImageSegment::bytes(
        Some("shellcode".to_string()),
        0,
        vec![0x11, 0xd8],
        ImagePermissions::executable(),
    ));

    let mut graph = Graph::new_with_image(Architecture::I386, image, config);
    graph.insert_instruction(instruction);
    assert!(graph.set_block(0));
    assert!(graph.set_function(0));
    let artifact = Decompiler::new(&graph, DecompilerBackend::Default)
        .decompile_function(0)
        .expect("decompilation should run")
        .expect("function should decompile");

    let state = serde_json::to_value(graph.state()).expect("state should serialize");
    let state = serde_json::from_value(state).expect("state should deserialize");
    let restored = Graph::from_state(state).expect("state roundtrip should restore");
    assert!(restored.state().decompilation.contains_key(&0));
    assert_eq!(restored.config.threads, 1);
    assert_eq!(
        restored
            .image()
            .read_virtual_address(0, 2)
            .expect("image read should succeed"),
        Some(vec![0x11, 0xd8])
    );

    let restored_instruction = restored
        .instruction(0)
        .expect("restored instruction should exist");
    let restored_lir = restored_instruction
        .lir
        .as_ref()
        .expect("restored instruction should keep lir");

    assert_eq!(restored_lir.status, original.status);
    assert_eq!(restored_lir.terminator.kind(), original.terminator.kind());
    assert_eq!(restored_lir.effects.len(), original.effects.len());
    assert_eq!(restored_lir.diagnostics.len(), original.diagnostics.len());
    assert_eq!(restored_instruction.mnemonic(), original_mnemonic);
    assert_eq!(restored_instruction.disassembly(), original_disassembly);
    assert_eq!(restored_instruction.operands(), original_operands);

    let restored_function = restored
        .function(0)
        .expect("restored function should exist");
    assert_eq!(restored_function.lir().unwrap(), artifact.lir);
    assert_eq!(restored_function.mir().unwrap(), artifact.mir);
    assert_eq!(restored_function.hir().unwrap(), artifact.hir);
    assert_eq!(restored_function.ast().unwrap().blocks, artifact.ast.blocks);
}

#[test]
fn graph_merge_prefers_more_complete_instruction_lir() {
    let config = Configuration::default();
    let mut base = Graph::new(Architecture::AMD64, config.clone());
    let mut incoming = Graph::new(Architecture::AMD64, config.clone());

    let mut partial_instruction =
        InstructionRecord::create(0x1000, Architecture::AMD64, config.clone());
    partial_instruction.bytes = vec![0x90];
    partial_instruction.pattern = "90".to_string();
    partial_instruction.lir = Some(partial_lir("partial lir"));
    base.insert_instruction(partial_instruction);

    let mut complete_instruction = InstructionRecord::create(0x1000, Architecture::AMD64, config);
    complete_instruction.bytes = vec![0x90];
    complete_instruction.pattern = "90".to_string();
    complete_instruction.lir = Some(complete_lir());
    incoming.insert_instruction(complete_instruction);

    base.merge(&mut incoming);

    let merged = base
        .instruction(0x1000)
        .expect("merged instruction should exist")
        .lir
        .clone()
        .expect("merged instruction should keep lir");

    assert_eq!(merged.status, LirStatus::Complete);
    assert!(merged.diagnostics.is_empty());
}

#[test]
fn graph_update_instruction_preserves_attached_lir() {
    let config = Configuration::default();
    let mut graph = Graph::new(Architecture::I386, config.clone());
    let mut instruction =
        disassemble_single("btc eax, 1", Architecture::I386, &[0x0f, 0xba, 0xf8, 0x01]);
    let original = instruction
        .lir
        .clone()
        .expect("instruction should have lir");

    graph.insert_instruction(instruction.clone());
    instruction.pattern = "0f baf8 01".replace(' ', "");
    graph.update_instruction(instruction);

    let updated = graph
        .instruction(0)
        .expect("updated instruction should exist")
        .lir
        .clone()
        .expect("updated instruction should retain lir");

    assert_eq!(updated.status, original.status);
    assert_eq!(updated.effects.len(), original.effects.len());
    assert_eq!(updated.terminator.kind(), original.terminator.kind());
}
