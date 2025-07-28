use binlex::lifters::vex::lifter::VexLifter;
use binlex::controlflow::{Instruction, Block, Function};
use binlex::global::{Architecture, Config};
use binlex::controlflow::graph::Graph;
use std::collections::{BTreeSet, BTreeMap};

fn test_graph() -> Graph {
    Graph::new(Architecture::AMD64, Config::default())
}

#[test]
fn test_lift_bytes_ret() {
    let lifter = VexLifter::new();
    let code = [0xC3u8]; // x86_64 "ret"
    let mut vta = libvex::TranslateArgs::new(lifter.arch, lifter.arch, lifter.endness);
    let irsb = vta.front_end(code.as_ptr(), 0x1000).ok();
    assert!(irsb.is_some());
    if let Some(irsb) = irsb {
        println!("IRSB for ret: {:?}", irsb);
        drop(irsb);
    }
}

#[test]
fn test_lift_instruction() {
    let instruction = Instruction {
        architecture: Architecture::AMD64,
        config: Config::default(),
        address: 0x2000,
        is_prologue: false,
        is_block_start: false,
        is_function_start: false,
        bytes: vec![0xC3],
        pattern: "c3".to_string(),
        is_return: true,
        is_call: false,
        is_jump: false,
        is_conditional: false,
        is_trap: false,
        functions: BTreeSet::new(),
        to: BTreeSet::new(),
        edges: 0,
    };
    let lifter = VexLifter::new();
    let mut vta = libvex::TranslateArgs::new(lifter.arch, lifter.arch, lifter.endness);
    let irsb = vta.front_end(instruction.bytes.as_ptr(), instruction.address).ok();
    assert!(irsb.is_some());
    if let Some(irsb) = irsb {
        println!("IRSB for instruction: {:?}", irsb);
        drop(irsb);
    }
}

#[test]
fn test_lift_block() {
    let graph = test_graph();
    let instruction = Instruction {
        architecture: Architecture::AMD64,
        config: Config::default(),
        address: 0x3000,
        is_prologue: false,
        is_block_start: false,
        is_function_start: false,
        bytes: vec![0xC3],
        pattern: "c3".to_string(),
        is_return: true,
        is_call: false,
        is_jump: false,
        is_conditional: false,
        is_trap: false,
        functions: BTreeSet::new(),
        to: BTreeSet::new(),
        edges: 0,
    };
    // Insert the instruction into the graph's listing at 0x3000
    graph.listing.insert(0x3000, instruction.clone());
    let block = Block {
        address: 0x3000,
        cfg: &graph,
        terminator: instruction,
    };
    let lifter = VexLifter::new();
    let mut vta = libvex::TranslateArgs::new(lifter.arch, lifter.arch, lifter.endness);
    let irsb = vta.front_end(block.bytes().as_ptr(), block.address).ok();
    assert!(irsb.is_some());
    if let Some(irsb) = irsb {
        println!("IRSB for block: {:?}", irsb);
        drop(irsb);
    }
}

#[test]
fn test_extract_block_addresses() {
    let graph = test_graph();
    let terminator = Instruction {
        architecture: Architecture::AMD64,
        config: Config::default(),
        address: 0x4000,
        is_prologue: false,
        is_block_start: false,
        is_function_start: false,
        bytes: vec![0xC3],
        pattern: "c3".to_string(),
        is_return: true,
        is_call: false,
        is_jump: false,
        is_conditional: false,
        is_trap: false,
        functions: BTreeSet::new(),
        to: BTreeSet::new(),
        edges: 0,
    };
    let block = Block {
        address: 0x4000,
        cfg: &graph,
        terminator,
    };
    let mut blocks_map = BTreeMap::new();
    blocks_map.insert(0x4000, block);
    let function = Function {
        address: 0x4000,
        cfg: &graph,
        blocks: blocks_map,
    };
    let mut blocks = Vec::new();
    for block in function.blocks.values() {
        let addr = block.address;
        let size = block.bytes().len() as u64;
        blocks.push((addr, size));
    }
    assert!(!blocks.is_empty());
    println!("Extracted block addresses: {:?}", blocks);
}

#[test]
fn test_lift_binlex_block_split_example() {
    let lifter = VexLifter::new();
    // Block: jz 0x4; nop; nop; ret
    let block_bytes = [0x74, 0x02, 0x90, 0x90, 0xc3];
    let block_address = 0x0u64;
    let mut vta = libvex::TranslateArgs::new(lifter.arch, lifter.arch, lifter.endness);
    let irsb = vta.front_end(block_bytes.as_ptr(), block_address).ok();
    assert!(irsb.is_some());
    if let Some(irsb) = irsb {
        println!("IRSB for binlex block split example: {:?}", irsb);
        drop(irsb);
    }
} 