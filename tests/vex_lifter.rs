#![cfg(not(target_os = "windows"))]

use binlex::controlflow::graph::Graph;
use binlex::controlflow::{Block, Function, InstructionRecord};
use binlex::irs::lir::{
    LirEffect, LirExpression, LirInstruction, LirLocation, LirStatus, LirTerminator,
};
use binlex::irs::vex::VexModule;
use binlex::{Architecture, Configuration};
use std::collections::BTreeMap;

fn test_config() -> Configuration {
    Configuration::default()
}

fn instruction(address: u64, bytes: &[u8]) -> InstructionRecord {
    let mut instruction =
        InstructionRecord::create(address, Architecture::AMD64, Configuration::default());
    instruction.bytes = bytes.to_vec();
    instruction.chromosome_mask = vec![0x00; bytes.len()];
    instruction.pattern = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("");
    instruction.is_return = bytes == [0xC3];
    instruction.lir = Some(LirInstruction {
        address: None,
        status: LirStatus::Complete,
        effects: vec![LirEffect::Set {
            dst: LirLocation::ProgramCounter { bits: 64 },
            expression: LirExpression::Const {
                value: address as u128 + bytes.len() as u128,
                bits: 64,
            },
        }],
        terminator: LirTerminator::Return { expression: None },
    });
    instruction
}

fn instruction_for_arch(
    architecture: Architecture,
    address: u64,
    bytes: &[u8],
) -> InstructionRecord {
    let mut instruction = instruction(address, bytes);
    instruction.architecture = architecture;
    instruction
}

fn single_block_graph(address: u64, bytes: &[u8]) -> Graph {
    let mut graph = Graph::new(Architecture::AMD64, test_config());
    graph.insert_instruction(instruction(address, bytes));
    graph
}

#[test]
fn lift_instruction_renders_vex_text() {
    let mut lifter = VexModule::with_config(None, test_config());
    let mut graph = Graph::new(Architecture::AMD64, test_config());
    graph.insert_instruction(instruction(0x1000, &[0xC3]));
    let instruction = graph.instruction(0x1000).expect("instruction should exist");
    lifter
        .populate_instruction(&instruction)
        .expect("instruction lift should succeed");
    let text = lifter.text();
    assert!(text.contains("instruction_1000"));
    assert!(text.contains("IRSB"));
}

#[test]
fn lift_block_renders_vex_text() {
    let graph = single_block_graph(0x2000, &[0xC3]);
    let terminator = graph.instruction(0x2000).expect("instruction should exist");
    let block = Block {
        address: 0x2000,
        cfg: &graph,
        terminator,
    };
    let mut lifter = VexModule::with_config(None, test_config());
    lifter
        .populate_block(&block)
        .expect("block lift should succeed");
    let text = lifter.text();
    assert!(text.contains("block_2000"));
    assert!(text.contains("IRSB"));
}

#[test]
fn lift_function_renders_vex_text() {
    let graph = single_block_graph(0x3000, &[0xC3]);
    let terminator = graph.instruction(0x3000).expect("instruction should exist");
    let block = Block {
        address: 0x3000,
        cfg: &graph,
        terminator,
    };
    let function = Function {
        address: 0x3000,
        cfg: &graph,
        blocks: BTreeMap::from([(0x3000, block)]),
    };

    let mut lifter = VexModule::with_config(None, test_config());
    lifter
        .populate_function(&function)
        .expect("function lift should succeed");

    let text = lifter.text();
    assert!(text.contains("function_3000"));
    assert!(text.contains("IRSB"));
}

#[test]
fn non_contiguous_function_is_supported() {
    let mut graph = Graph::new(Architecture::AMD64, test_config());
    graph.insert_instruction(instruction(0x4000, &[0x90, 0xC3]));
    graph.insert_instruction(instruction(0x5000, &[0xC3]));

    let first_terminator = graph.instruction(0x4000).expect("instruction should exist");
    let first = Block {
        address: 0x4000,
        cfg: &graph,
        terminator: first_terminator,
    };
    let second_terminator = graph.instruction(0x5000).expect("instruction should exist");
    let second = Block {
        address: 0x5000,
        cfg: &graph,
        terminator: second_terminator,
    };
    let function = Function {
        address: 0x4000,
        cfg: &graph,
        blocks: BTreeMap::from([(0x4000, first), (0x5000, second)]),
    };

    let mut lifter = VexModule::with_config(None, test_config());
    lifter
        .populate_function(&function)
        .expect("non-contiguous function should lift");
    let text = lifter.text();
    assert!(text.contains("; block block_4000"));
    assert!(text.contains("; block block_5000"));
}

#[test]
fn cil_function_renders_vex_text() {
    let mut graph = Graph::new(Architecture::CIL, test_config());
    graph.insert_instruction(instruction_for_arch(Architecture::CIL, 0x7000, &[0x02]));
    let terminator = graph.instruction(0x7000).expect("instruction should exist");
    let block = Block {
        address: 0x7000,
        cfg: &graph,
        terminator,
    };
    let function = Function {
        address: 0x7000,
        cfg: &graph,
        blocks: BTreeMap::from([(0x7000, block)]),
    };

    let mut lifter = VexModule::with_config(None, test_config());
    lifter
        .populate_function(&function)
        .expect("cil function should lift to vex text");
    let text = lifter.text();
    assert!(text.contains("; function function_7000"));
    assert!(text.contains("IRSB {"));
}

#[test]
fn vex_lifter_accessors_render_entity_text() {
    let instruction_config = Configuration::default();
    let mut instruction_graph = Graph::new(Architecture::AMD64, instruction_config.clone());
    let mut lifted_instruction = instruction(0x8000, &[0xC3]);
    lifted_instruction.config = instruction_config.clone();
    instruction_graph.insert_instruction(lifted_instruction);
    let instruction_text = instruction_graph
        .instruction(0x8000)
        .expect("instruction should exist")
        .vex()
        .expect("instruction should lift")
        .text();
    assert!(instruction_text.contains("instruction_8000"));

    let block_config = Configuration::default();
    let mut block_graph = Graph::new(Architecture::AMD64, block_config);
    block_graph.insert_instruction(instruction(0x8100, &[0xC3]));
    let block_terminator = block_graph
        .instruction(0x8100)
        .expect("instruction should exist");
    let block = Block {
        address: 0x8100,
        cfg: &block_graph,
        terminator: block_terminator,
    };
    let block_text = block.vex().expect("block should lift").text();
    assert!(block_text.contains("block_8100"));

    let function_config = Configuration::default();
    let mut function_graph = Graph::new(Architecture::AMD64, function_config);
    function_graph.insert_instruction(instruction(0x8200, &[0xC3]));
    let function_terminator = function_graph
        .instruction(0x8200)
        .expect("instruction should exist");
    let function_block = Block {
        address: 0x8200,
        cfg: &function_graph,
        terminator: function_terminator,
    };
    let function = Function {
        address: 0x8200,
        cfg: &function_graph,
        blocks: BTreeMap::from([(0x8200, function_block)]),
    };
    let function_text = function.vex().expect("function should lift").text();
    assert!(function_text.contains("function_8200"));
}
