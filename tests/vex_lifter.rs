#![cfg(not(target_os = "windows"))]

use binlex::controlflow::graph::Graph;
use binlex::controlflow::{Block, Function, Instruction};
use binlex::lifters::vex::Lifter;
use binlex::semantics::{
    InstructionSemantics, SemanticEffect, SemanticExpression, SemanticLocation, SemanticStatus,
    SemanticTerminator,
};
use binlex::{Architecture, Config};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

fn test_config() -> Config {
    let mut config = Config::default();
    let processor_dir = std::env::current_exe()
        .expect("test binary should have a path")
        .parent()
        .and_then(|path| path.parent())
        .map(PathBuf::from)
        .expect("test binary should be in target/<profile>/deps");
    config.processors.enabled = true;
    config.processors.path = Some(processor_dir.to_string_lossy().into_owned());
    config.processors.processes = 1;
    config.processors.compression = true;
    config
}

#[test]
fn vex_config_defaults_match_expected_shape() {
    let config = Config::default();
    assert!(config.lifters.vex.enabled);
    assert!(!config.instructions.lifters.vex.enabled);
    assert!(!config.blocks.lifters.vex.enabled);
    assert!(!config.functions.lifters.vex.enabled);
}

#[test]
fn vex_global_disable_blocks_lifting() {
    let mut config = Config::default();
    config.lifters.vex.enabled = false;
    let mut lifter = Lifter::new(config);
    let error = lifter
        .lift_instruction(&instruction(0x1800, &[0xC3]))
        .expect_err("disabled vex lifter should fail");
    assert!(error.to_string().contains("disabled"));
}

fn instruction(address: u64, bytes: &[u8]) -> Instruction {
    Instruction {
        architecture: Architecture::AMD64,
        config: Config::default(),
        address,
        is_prologue: false,
        is_block_start: false,
        is_function_start: false,
        bytes: bytes.to_vec(),
        chromosome_mask: vec![0x00; bytes.len()],
        pattern: bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(""),
        is_return: bytes == [0xC3],
        is_call: false,
        is_jump: false,
        is_conditional: false,
        is_trap: false,
        has_indirect_target: false,
        functions: BTreeSet::new(),
        to: BTreeSet::new(),
        edges: 0,
        semantics: Some(InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::ProgramCounter { bits: 64 },
                expression: SemanticExpression::Const {
                    value: address as u128 + bytes.len() as u128,
                    bits: 64,
                },
            }],
            terminator: SemanticTerminator::Return { expression: None },
            diagnostics: Vec::new(),
        }),
    }
}

fn instruction_for_arch(architecture: Architecture, address: u64, bytes: &[u8]) -> Instruction {
    let mut instruction = instruction(address, bytes);
    instruction.architecture = architecture;
    instruction
}

fn single_block_graph(address: u64, bytes: &[u8]) -> Graph {
    let graph = Graph::new(Architecture::AMD64, test_config());
    graph.listing.insert(address, instruction(address, bytes));
    graph
}

#[test]
fn lift_instruction_renders_vex_text() {
    let mut lifter = Lifter::new(test_config());
    let instruction = instruction(0x1000, &[0xC3]);
    lifter
        .lift_instruction(&instruction)
        .expect("instruction lift should succeed");
    let text = lifter.text();
    assert!(text.contains("instruction_1000"));
    assert!(text.contains("IRSB"));
}

#[test]
fn lift_block_renders_vex_text() {
    let graph = single_block_graph(0x2000, &[0xC3]);
    let block = Block {
        address: 0x2000,
        cfg: &graph,
        terminator: instruction(0x2000, &[0xC3]),
    };
    let mut lifter = Lifter::new(test_config());
    lifter
        .lift_block(&block)
        .expect("block lift should succeed");
    let text = lifter.text();
    assert!(text.contains("block_2000"));
    assert!(text.contains("IRSB"));
}

#[test]
fn lift_function_renders_vex_text() {
    let graph = single_block_graph(0x3000, &[0xC3]);
    let block = Block {
        address: 0x3000,
        cfg: &graph,
        terminator: instruction(0x3000, &[0xC3]),
    };
    let function = Function {
        address: 0x3000,
        cfg: &graph,
        blocks: BTreeMap::from([(0x3000, block)]),
    };

    let mut lifter = Lifter::new(test_config());
    lifter
        .lift_function(&function)
        .expect("function lift should succeed");

    let text = lifter.text();
    assert!(text.contains("function_3000"));
    assert!(text.contains("IRSB"));
}

#[test]
fn non_contiguous_function_is_supported() {
    let graph = Graph::new(Architecture::AMD64, test_config());
    graph
        .listing
        .insert(0x4000, instruction(0x4000, &[0x90, 0xC3]));
    graph.listing.insert(0x5000, instruction(0x5000, &[0xC3]));

    let first = Block {
        address: 0x4000,
        cfg: &graph,
        terminator: instruction(0x4000, &[0x90, 0xC3]),
    };
    let second = Block {
        address: 0x5000,
        cfg: &graph,
        terminator: instruction(0x5000, &[0xC3]),
    };
    let function = Function {
        address: 0x4000,
        cfg: &graph,
        blocks: BTreeMap::from([(0x4000, first), (0x5000, second)]),
    };

    let mut lifter = Lifter::new(test_config());
    lifter
        .lift_function(&function)
        .expect("non-contiguous function should lift");
    let text = lifter.text();
    assert!(text.contains("; block 0x4000"));
    assert!(text.contains("; block 0x5000"));
}

#[test]
fn cil_function_renders_vex_text() {
    let graph = Graph::new(Architecture::CIL, test_config());
    graph.listing.insert(
        0x7000,
        instruction_for_arch(Architecture::CIL, 0x7000, &[0x02]),
    );
    let block = Block {
        address: 0x7000,
        cfg: &graph,
        terminator: instruction_for_arch(Architecture::CIL, 0x7000, &[0x02]),
    };
    let function = Function {
        address: 0x7000,
        cfg: &graph,
        blocks: BTreeMap::from([(0x7000, block)]),
    };

    let mut lifter = Lifter::new(test_config());
    lifter
        .lift_function(&function)
        .expect("cil function should lift to vex text");
    let text = lifter.text();
    assert!(text.contains("; function function_7000 cil 0x7000"));
    assert!(text.contains("IRSB {"));
}

#[test]
fn vex_json_emission_respects_entity_flags() {
    let mut instruction_config = Config::default();
    instruction_config.instructions.lifters.vex.enabled = true;
    let lifted_instruction = Instruction {
        config: instruction_config.clone(),
        ..instruction(0x8000, &[0xC3])
    };
    let instruction_json =
        serde_json::to_value(lifted_instruction.process()).expect("serialize instruction");
    assert!(
        instruction_json["lifters"]["vex"]["text"]
            .as_str()
            .expect("instruction vex text")
            .contains("instruction_8000")
    );

    let mut block_config = Config::default();
    block_config.blocks.lifters.vex.enabled = true;
    let block_graph = Graph::new(Architecture::AMD64, block_config);
    block_graph
        .listing
        .insert(0x8100, instruction(0x8100, &[0xC3]));
    let block = Block {
        address: 0x8100,
        cfg: &block_graph,
        terminator: instruction(0x8100, &[0xC3]),
    };
    let block_json = serde_json::to_value(block.process()).expect("serialize block");
    assert!(
        block_json["lifters"]["vex"]["text"]
            .as_str()
            .expect("block vex text")
            .contains("block_8100")
    );

    let mut function_config = Config::default();
    function_config.functions.lifters.vex.enabled = true;
    let function_graph = Graph::new(Architecture::AMD64, function_config);
    function_graph
        .listing
        .insert(0x8200, instruction(0x8200, &[0xC3]));
    let function_block = Block {
        address: 0x8200,
        cfg: &function_graph,
        terminator: instruction(0x8200, &[0xC3]),
    };
    let function = Function {
        address: 0x8200,
        cfg: &function_graph,
        blocks: BTreeMap::from([(0x8200, function_block)]),
    };
    let function_json = serde_json::to_value(function.process()).expect("serialize function");
    assert!(
        function_json["lifters"]["vex"]["text"]
            .as_str()
            .expect("function vex text")
            .contains("function_8200")
    );
}
