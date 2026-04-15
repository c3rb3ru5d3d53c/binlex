use std::collections::{BTreeMap, BTreeSet};

use binlex::controlflow::{Block, Function, Graph, Instruction};
use binlex::lifters::llvm::Lifter;
use binlex::{Architecture, Config};

fn disassemble_graph(architecture: Architecture, bytes: &[u8]) -> Graph {
    let config = Config::default();
    let mut ranges = BTreeMap::new();
    ranges.insert(0, bytes.len() as u64);

    let disassembler = binlex::disassemblers::capstone::Disassembler::from_bytes(
        architecture,
        bytes,
        ranges,
        config.clone(),
    )
    .expect("disassembler");

    let mut graph = Graph::new(architecture, config);
    let mut entrypoints = BTreeSet::new();
    entrypoints.insert(0);
    disassembler
        .disassemble(entrypoints, &mut graph)
        .expect("graph should disassemble");
    graph
}

fn build_noncontiguous_function_graph() -> Graph {
    let config = Config::default();
    let mut graph = Graph::new(Architecture::I386, config.clone());

    let mut jump = Instruction::create(0x1000, Architecture::I386, config.clone());
    jump.bytes = vec![0xE9, 0xFB, 0x0F, 0x00, 0x00];
    jump.pattern = "e9fb0f0000".to_string();
    jump.is_jump = true;
    jump.to.insert(0x2000);
    jump.edges = jump.blocks().len();
    graph.insert_instruction(jump);

    let mut ret = Instruction::create(0x2000, Architecture::I386, config);
    ret.bytes = vec![0xC3];
    ret.pattern = "c3".to_string();
    ret.is_return = true;
    graph.insert_instruction(ret);

    assert!(graph.set_block(0x1000));
    assert!(graph.set_block(0x2000));
    assert!(graph.set_function(0x1000));

    graph
}

#[test]
fn llvm_lifter_renders_instruction_block_and_function_ir() {
    let graph = disassemble_graph(Architecture::I386, &[0x31, 0xc0, 0x40, 0xc3]); // xor eax,eax; inc eax; ret
    let instruction = graph.get_instruction(0).expect("instruction");
    let block = Block::new(0, &graph).expect("block");
    let function = Function::new(0, &graph).expect("function");

    let mut instruction_lifter = Lifter::new(Config::default());
    instruction_lifter
        .lift_instruction(&instruction)
        .expect("instruction should lift");
    instruction_lifter.verify().expect("instruction module should verify");
    let instruction_ir = instruction_lifter.text();
    let instruction_bc = instruction_lifter.bitcode();
    assert!(instruction_ir.contains("define void @instruction_0()"));
    assert!(instruction_ir.contains("call void @binlex_instruction_address(i64 0)"));
    assert!(instruction_ir.contains("ret void"));
    assert_eq!(&instruction_bc[..4], b"BC\xc0\xde");
    let instruction_normalized = instruction_lifter
        .normalized()
        .expect("normalized instruction module");
    let instruction_normalized_text = instruction_normalized.text();
    assert_eq!(&instruction_normalized.bitcode()[..4], b"BC\xc0\xde");
    assert!(instruction_normalized_text.contains("define void @f0()"));
    assert!(instruction_normalized_text.contains("call void @binlex_instruction_address(i64 0)"));

    let mut block_lifter = Lifter::new(Config::default());
    block_lifter.lift_block(&block).expect("block should lift");
    block_lifter.verify().expect("block module should verify");
    let block_ir = block_lifter.text();
    assert!(block_ir.contains("define void @block_0()"));
    assert!(block_ir.contains("call void @binlex_instruction_address(i64 0)"));
    assert!(block_ir.contains("call void @binlex_instruction_address(i64 2)"));

    let mut function_lifter = Lifter::new(Config::default());
    function_lifter
        .lift_function(&function)
        .expect("function should lift");
    function_lifter.verify().expect("function module should verify");
    let function_ir = function_lifter.text();
    let function_bc = function_lifter.bitcode();
    assert!(function_ir.contains("define void @function_0()"));
    assert!(function_ir.contains("call void @binlex_instruction_address(i64 0)"));
    assert!(function_ir.contains("call void @binlex_instruction_address(i64 2)"));
    assert!(function_ir.contains("entry:"));
    assert!(function_ir.contains("block_0:"));
    assert!(function_ir.contains("source_filename = \"binlex\""));
    assert_eq!(&function_bc[..4], b"BC\xc0\xde");
    let function_normalized = function_lifter
        .normalized()
        .expect("normalized function module");
    let function_normalized_text = function_normalized.text();
    assert!(function_normalized_text.contains("define void @f0()"));
    assert!(function_normalized_text.contains("b0:"));
    assert!(function_normalized_text.contains("call void @binlex_instruction_address(i64 0)"));
    assert!(function_normalized_text.contains("call void @binlex_instruction_address(i64 1)"));
}

#[test]
fn llvm_lifter_handles_noncontiguous_functions() {
    let graph = build_noncontiguous_function_graph();
    let function = Function::new(0x1000, &graph).expect("function");

    assert!(!function.contiguous(), "function should be non-contiguous");
    assert_eq!(function.block_addresses(), vec![0x1000, 0x2000]);

    let mut lifter = Lifter::new(Config::default());
    lifter
        .lift_function(&function)
        .expect("non-contiguous function should lift");
    lifter.verify().expect("non-contiguous function module should verify");

    let ir = lifter.text();
    assert!(ir.contains("define void @function_1000()"));
    assert!(ir.contains("entry:"));
    assert!(ir.contains("block_1000:"));
    assert!(ir.contains("block_2000:"));
    assert!(ir.contains("br label %block_1000"));
    assert!(ir.contains("br label %block_2000"));
    assert!(ir.contains("call void @binlex_instruction_address(i64 4096)"));
    assert!(ir.contains("call void @binlex_instruction_address(i64 8192)"));
    let normalized = lifter.normalized().expect("normalized non-contiguous function");
    let normalized_text = normalized.text();
    assert!(normalized_text.contains("define void @f0()"));
    assert!(normalized_text.contains("b0:"));
    assert!(normalized_text.contains("b1:"));
    assert!(normalized_text.contains("call void @binlex_instruction_address(i64 0)"));
    assert!(normalized_text.contains("call void @binlex_instruction_address(i64 1)"));
}

#[test]
fn llvm_lifter_optimizers_chain_and_preserve_outputs() {
    let graph = disassemble_graph(Architecture::I386, &[0x31, 0xc0, 0x40, 0xc3]);
    let function = Function::new(0, &graph).expect("function");

    let mut lifter = Lifter::new(Config::default());
    lifter
        .lift_function(&function)
        .expect("function should lift before optimization");

    let populated = lifter
        .optimizers()
        .expect("optimizer namespace")
        .mem2reg()
        .expect("mem2reg")
        .instcombine()
        .expect("instcombine")
        .cfg()
        .expect("cfg")
        .gvn()
        .expect("gvn")
        .sroa()
        .expect("sroa")
        .dce()
        .expect("dce")
        .into_lifter();

    populated.verify().expect("optimized module should verify");

    let text = populated.text();
    assert!(text.contains("define void @function_0()"));
    assert_eq!(&populated.bitcode()[..4], b"BC\xc0\xde");

    let normalized = populated.normalized().expect("normalized optimized module");
    assert!(normalized.text().contains("define void @f0()"));
}

#[test]
fn llvm_json_output_respects_entity_config_flags() {
    let mut config = Config::default();
    let graph = {
        let mut ranges = BTreeMap::new();
        let bytes = [0x31, 0xc0, 0x40, 0xc3];
        ranges.insert(0, bytes.len() as u64);
        let disassembler = binlex::disassemblers::capstone::Disassembler::from_bytes(
            Architecture::I386,
            &bytes,
            ranges,
            config.clone(),
        )
        .expect("disassembler");
        let mut graph = Graph::new(Architecture::I386, config.clone());
        let mut entrypoints = BTreeSet::new();
        entrypoints.insert(0);
        disassembler
            .disassemble(entrypoints, &mut graph)
            .expect("graph should disassemble");
        graph
    };

    let instruction = graph.get_instruction(0).expect("instruction");
    let block = Block::new(0, &graph).expect("block");
    let function = Function::new(0, &graph).expect("function");

    let instruction_json = serde_json::to_value(instruction.process()).expect("serialize instruction");
    let block_json = serde_json::to_value(block.process()).expect("serialize block");
    let function_json = serde_json::to_value(function.process()).expect("serialize function");
    assert!(instruction_json.get("lifters").is_none());
    assert!(block_json.get("lifters").is_none());
    assert!(function_json.get("lifters").is_none());

    config.instructions.lifters.llvm.enabled = true;
    config.blocks.lifters.llvm.enabled = true;
    config.functions.lifters.llvm.enabled = true;
    config.functions.lifters.llvm.normalized.enabled = true;

    let graph = {
        let mut ranges = BTreeMap::new();
        let bytes = [0x31, 0xc0, 0x40, 0xc3];
        ranges.insert(0, bytes.len() as u64);
        let disassembler = binlex::disassemblers::capstone::Disassembler::from_bytes(
            Architecture::I386,
            &bytes,
            ranges,
            config.clone(),
        )
        .expect("disassembler");
        let mut graph = Graph::new(Architecture::I386, config.clone());
        let mut entrypoints = BTreeSet::new();
        entrypoints.insert(0);
        disassembler
            .disassemble(entrypoints, &mut graph)
            .expect("graph should disassemble");
        graph
    };

    let instruction = graph.get_instruction(0).expect("instruction");
    let block = Block::new(0, &graph).expect("block");
    let function = Function::new(0, &graph).expect("function");

    let instruction_json = serde_json::to_value(instruction.process()).expect("serialize instruction");
    let block_json = serde_json::to_value(block.process()).expect("serialize block");
    let function_json = serde_json::to_value(function.process()).expect("serialize function");

    assert_eq!(
        instruction_json["lifters"]["llvm"]["text"].as_str().map(|s| s.contains("@instruction_0()")),
        Some(true)
    );
    assert_eq!(
        block_json["lifters"]["llvm"]["text"].as_str().map(|s| s.contains("@block_0()")),
        Some(true)
    );
    assert_eq!(
        function_json["lifters"]["llvm"]["text"].as_str().map(|s| s.contains("@function_0()")),
        Some(true)
    );
    assert_eq!(
        function_json["lifters"]["llvm"]["normalized"]["text"]
            .as_str()
            .map(|s| s.contains("@f0()")),
        Some(true)
    );
    assert_eq!(
        instruction_json
            .get("lifters")
            .and_then(|value| value.get("llvm"))
            .and_then(|value| value.get("normalized")),
        None
    );
    assert_eq!(
        block_json
            .get("lifters")
            .and_then(|value| value.get("llvm"))
            .and_then(|value| value.get("normalized")),
        None
    );
}
