#![cfg(not(target_os = "windows"))]

use binlex::controlflow::graph::Graph;
use binlex::controlflow::{Block, Function, Instruction};
use binlex::lifters::vex::{Lifter, LifterJsonDeserializer};
use binlex::{Architecture, Config};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

fn test_graph() -> Graph {
    Graph::new(Architecture::AMD64, test_config())
}

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
    let vex = config
        .processors
        .ensure_processor("vex")
        .expect("vex processor config should exist");
    vex.enabled = true;
    vex.blocks.enabled = true;
    vex.functions.enabled = true;
    config
}

#[test]
fn test_lift_bytes_ret() {
    let mut vex = Lifter::new(Architecture::AMD64, &[0xC3u8], 0x1000, test_config()).unwrap();
    let irsb = vex.ir().ok(); // x86_64 "ret"
    assert!(irsb.is_some());
    if let Some(irsb) = irsb {
        println!("IRSB for ret: {:?}", irsb);
    }
}

#[test]
fn test_lifter_process() {
    let mut lifter = Lifter::new(Architecture::AMD64, &[0xC3u8], 0x1000, test_config()).unwrap();
    let json = lifter.process().unwrap();
    assert_eq!(json.architecture, "amd64");
    assert_eq!(json.address, 0x1000);
    assert_eq!(json.bytes, "c3");
    assert!(!json.ir.is_empty());
}

#[test]
fn test_vex_json_deserializer_round_trip() {
    let config = test_config();
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
        test_config(),
    )
    .unwrap();
    let irsb = vex.ir().ok();
    assert!(irsb.is_some());
    if let Some(irsb) = irsb {
        println!("IRSB for instruction: {:?}", irsb);
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
    let mut vex = Lifter::new(
        Architecture::AMD64,
        &block_bytes,
        block.address,
        test_config(),
    )
    .unwrap();
    let irsb = vex.ir().ok();
    assert!(irsb.is_some());
    if let Some(irsb) = irsb {
        println!("IRSB for block: {:?}", irsb);
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
    let mut vex = Lifter::new(
        Architecture::AMD64,
        &block_bytes,
        block_address,
        test_config(),
    )
    .unwrap();
    let irsb = vex.ir().ok();
    assert!(irsb.is_some());
    if let Some(irsb) = irsb {
        println!("IRSB for binlex block split example: {:?}", irsb);
    }
}

#[test]
fn test_worker_lifter_process() {
    let config = test_config();
    let mut lifter = Lifter::new(Architecture::AMD64, &[0xC3u8], 0x1000, config).unwrap();
    let json = lifter.process().unwrap();
    assert_eq!(json.architecture, "amd64");
    assert_eq!(json.bytes, "c3");
    assert!(!json.ir.is_empty());
}

#[test]
fn test_function_process_populates_vex_lifters() {
    let graph = test_graph();
    let instruction = Instruction {
        architecture: Architecture::AMD64,
        config: Config::default(),
        address: 0x5000,
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
    graph.listing.insert(0x5000, instruction.clone());
    let block = Block {
        address: 0x5000,
        cfg: &graph,
        terminator: instruction,
    };
    let mut blocks_map = BTreeMap::new();
    blocks_map.insert(0x5000, block);
    let function = Function {
        address: 0x5000,
        cfg: &graph,
        blocks: blocks_map,
    };

    let json = function.process();
    let processors = json.processors.expect("processors should be populated");
    let vex = processors
        .get("vex")
        .expect("vex processor output should be present");
    let ir = vex
        .get("ir")
        .and_then(|value| value.as_str())
        .expect("vex processor output should include an ir string");

    assert!(!ir.is_empty());
}

#[test]
fn test_block_process_populates_vex_lifters() {
    let graph = test_graph();
    let instruction = Instruction {
        architecture: Architecture::AMD64,
        config: Config::default(),
        address: 0x5100,
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
    graph.listing.insert(0x5100, instruction.clone());
    let block = Block {
        address: 0x5100,
        cfg: &graph,
        terminator: instruction,
    };

    let json = block.process();
    let processors = json.processors.expect("processors should be populated");
    let vex = processors
        .get("vex")
        .expect("vex processor output should be present");
    let ir = vex
        .get("ir")
        .and_then(|value| value.as_str())
        .expect("vex processor output should include an ir string");

    assert!(!ir.is_empty());
}

#[test]
fn test_function_json_omits_disabled_optional_keys() {
    let mut config = test_config();
    config.chromosomes.vector.enabled = false;
    config.functions.entropy.enabled = false;
    let graph = Graph::new(Architecture::AMD64, config);
    let instruction = Instruction {
        architecture: Architecture::AMD64,
        config: Config::default(),
        address: 0x6000,
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
    graph.listing.insert(0x6000, instruction.clone());
    let block = Block {
        address: 0x6000,
        cfg: &graph,
        terminator: instruction,
    };
    let mut blocks_map = BTreeMap::new();
    blocks_map.insert(0x6000, block);
    let function = Function {
        address: 0x6000,
        cfg: &graph,
        blocks: blocks_map,
    };

    let value: serde_json::Value =
        serde_json::from_str(&function.json().expect("function json should serialize"))
            .expect("function json should parse");

    assert!(value.get("entropy").is_none());
    assert!(
        value
            .get("chromosome")
            .and_then(|chromosome| chromosome.get("vector"))
            .is_none()
    );
}

#[test]
fn test_function_direct_accessors_ignore_serialization_flags() {
    let mut config = Config::default();
    config.functions.entropy.enabled = false;
    config.functions.sha256.enabled = false;
    config.functions.tlsh.enabled = false;
    config.functions.minhash.enabled = false;
    let graph = Graph::new(Architecture::AMD64, config);
    let instruction = Instruction {
        architecture: Architecture::AMD64,
        config: Config::default(),
        address: 0x6100,
        is_prologue: false,
        is_block_start: false,
        is_function_start: false,
        bytes: vec![0x3A, 0x7F, 0x92, 0x5C, 0xE4, 0xA1, 0xD8, 0x47, 0x29, 0xB3],
        pattern: "3a7f925ce4a1d84729b3".to_string(),
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
    graph.listing.insert(0x6100, instruction.clone());
    let block = Block {
        address: 0x6100,
        cfg: &graph,
        terminator: instruction,
    };
    let mut blocks_map = BTreeMap::new();
    blocks_map.insert(0x6100, block);
    let function = Function {
        address: 0x6100,
        cfg: &graph,
        blocks: blocks_map,
    };

    assert!(function.entropy().is_some());
    assert!(function.sha256().is_some());
    assert!(function.tlsh().is_some());
    assert!(function.minhash().is_some());

    let value: serde_json::Value =
        serde_json::from_str(&function.json().expect("function json should serialize"))
            .expect("function json should parse");
    assert!(value.get("entropy").is_none());
    assert!(value.get("sha256").is_none());
    assert!(value.get("tlsh").is_none());
    assert!(value.get("minhash").is_none());
}

#[test]
fn test_block_direct_accessors_ignore_serialization_flags() {
    let mut config = Config::default();
    config.blocks.entropy.enabled = false;
    config.blocks.sha256.enabled = false;
    config.blocks.tlsh.enabled = false;
    config.blocks.minhash.enabled = false;
    let graph = Graph::new(Architecture::AMD64, config);
    let instruction = Instruction {
        architecture: Architecture::AMD64,
        config: Config::default(),
        address: 0x6200,
        is_prologue: false,
        is_block_start: false,
        is_function_start: false,
        bytes: vec![0x3A, 0x7F, 0x92, 0x5C, 0xE4, 0xA1, 0xD8, 0x47, 0x29, 0xB3],
        pattern: "3a7f925ce4a1d84729b3".to_string(),
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
    graph.listing.insert(0x6200, instruction.clone());
    let block = Block {
        address: 0x6200,
        cfg: &graph,
        terminator: instruction,
    };

    assert!(block.entropy().is_some());
    assert!(block.sha256().is_some());
    assert!(block.tlsh().is_some());
    assert!(block.minhash().is_some());

    let value: serde_json::Value =
        serde_json::from_str(&block.json().expect("block json should serialize"))
            .expect("block json should parse");
    assert!(value.get("entropy").is_none());
    assert!(value.get("sha256").is_none());
    assert!(value.get("tlsh").is_none());
    assert!(value.get("minhash").is_none());
}
