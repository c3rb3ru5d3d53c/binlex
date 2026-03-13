#![cfg(not(target_os = "windows"))]

use binlex::controlflow::graph::Graph;
use binlex::controlflow::{Block, Function, Instruction};
use binlex::global::{Architecture, Config};
use binlex::lifters::vex::{Lifter, LifterJsonDeserializer};
use std::collections::{BTreeMap, BTreeSet};

fn test_graph() -> Graph {
    Graph::new(Architecture::AMD64, Config::default())
}

#[test]
fn test_lift_bytes_ret() {
    let mut vex = Lifter::new(Architecture::AMD64, &[0xC3u8], 0x1000, Config::default()).unwrap();
    let irsb = vex.ir().ok(); // x86_64 "ret"
    assert!(irsb.is_some());
    if let Some(irsb) = irsb {
        println!("IRSB for ret: {:?}", irsb);
        drop(irsb);
    }
}

#[test]
fn test_lifter_process() {
    let mut lifter =
        Lifter::new(Architecture::AMD64, &[0xC3u8], 0x1000, Config::default()).unwrap();
    let json = lifter.process().unwrap();
    assert_eq!(json.architecture, "amd64");
    assert_eq!(json.address, 0x1000);
    assert_eq!(json.bytes, "c3");
    assert!(!json.ir.is_empty());
}

#[test]
fn test_vex_json_deserializer_round_trip() {
    let config = Config::default();
    let mut lifter = Lifter::new(Architecture::AMD64, &[0xC3u8], 0x1000, config.clone()).unwrap();
    let serialized = serde_json::to_string(&lifter.process().unwrap()).unwrap();
    let deserialized = LifterJsonDeserializer::new(serialized, config).unwrap();
    assert_eq!(deserialized.architecture().unwrap(), Architecture::AMD64);
    assert_eq!(deserialized.address(), 0x1000);
    assert_eq!(deserialized.bytes().unwrap(), vec![0xC3]);
    assert!(!deserialized.ir().unwrap().is_empty());
    assert_eq!(deserialized.process().unwrap().bytes, "c3");
}

#[test]
fn test_lifter_json_deserializer_rejects_unsupported_architecture() {
    let json = r#"{"architecture":"cil","address":4096,"bytes":"c3","ir":"ignored"}"#;
    let result = LifterJsonDeserializer::new(json.to_string(), Config::default());
    assert!(result.is_err());
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
        has_indirect_target: false,
        functions: BTreeSet::new(),
        to: BTreeSet::new(),
        edges: 0,
    };
    let mut vex = Lifter::new(
        Architecture::AMD64,
        &instruction.bytes,
        instruction.address,
        Config::default(),
    )
    .unwrap();
    let irsb = vex.ir().ok();
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
        has_indirect_target: false,
        functions: BTreeSet::new(),
        to: BTreeSet::new(),
        edges: 0,
    };
    graph.listing.insert(0x3000, instruction.clone());
    let block = Block {
        address: 0x3000,
        cfg: &graph,
        terminator: instruction,
    };
    let block_bytes = block.bytes();
    let mut vex =
        Lifter::new(Architecture::AMD64, &block_bytes, block.address, Config::default()).unwrap();
    let irsb = vex.ir().ok();
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
        has_indirect_target: false,
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
    // Block: jz 0x4; nop; nop; ret
    let block_bytes = [0x74, 0x02, 0x90, 0x90, 0xc3];
    let block_address = 0x1000u64;
    let mut vex =
        Lifter::new(Architecture::AMD64, &block_bytes, block_address, Config::default()).unwrap();
    let irsb = vex.ir().ok();
    assert!(irsb.is_some());
    if let Some(irsb) = irsb {
        println!("IRSB for binlex block split example: {:?}", irsb);
        drop(irsb);
    }
}
