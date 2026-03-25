#![cfg(not(target_os = "windows"))]

use binlex::controlflow::{Graph, Instruction};
use binlex::processor::ProcessorTarget;
use binlex::{Architecture, Config};
use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

fn vex_processor_dir() -> String {
    static PROCESSOR_DIR: OnceLock<String> = OnceLock::new();

    PROCESSOR_DIR
        .get_or_init(|| {
            let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            let processor_path = manifest_dir
                .join("target")
                .join("debug")
                .join("binlex-processor-vex");
            if processor_path.exists() {
                return processor_path
                    .parent()
                    .expect("processor binary should have a parent directory")
                    .to_string_lossy()
                    .into_owned();
            }
            let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
            let status = Command::new(cargo)
                .current_dir(&manifest_dir)
                .args([
                    "build",
                    "-p",
                    "binlex-processor-vex",
                    "--bin",
                    "binlex-processor-vex",
                ])
                .status()
                .expect("cargo should build binlex-processor-vex");
            assert!(status.success(), "binlex-processor-vex binary should build");

            processor_path
                .parent()
                .expect("processor binary should have a parent directory")
                .to_string_lossy()
                .into_owned()
        })
        .clone()
}

fn test_config() -> Config {
    let mut config = Config::default();
    config.processors.enabled = true;
    config.processors.path = Some(vex_processor_dir());
    config.processors.processes = 1;
    config.processors.compression = true;
    for processor in config.processors.processors.values_mut() {
        processor.enabled = false;
        processor.instructions.enabled = false;
        processor.blocks.enabled = false;
        processor.functions.enabled = false;
    }
    let vex = config
        .processors
        .ensure_processor("vex")
        .expect("vex processor config should exist");
    vex.enabled = true;
    vex.instructions.enabled = true;
    vex.blocks.enabled = true;
    vex.functions.enabled = true;
    config
}

fn build_single_return_graph() -> Graph {
    let config = test_config();
    let mut graph = Graph::new(Architecture::AMD64, config.clone());
    let mut instruction = Instruction::create(0x1000, Architecture::AMD64, config);
    instruction.bytes = vec![0xC3];
    instruction.pattern = "c3".to_string();
    instruction.is_return = true;
    graph.insert_instruction(instruction);
    assert!(graph.set_block(0x1000));
    assert!(graph.set_function(0x1000));
    graph
}

#[test]
fn graph_functions_materialize_processor_results_on_first_access() {
    let graph = build_single_return_graph();

    assert!(
        graph
            .processor_outputs(ProcessorTarget::Function, 0x1000)
            .is_none()
    );

    let functions = graph.functions();
    assert_eq!(functions.len(), 1);

    let outputs = graph
        .processor_outputs(ProcessorTarget::Function, 0x1000)
        .expect("function processor outputs should exist");
    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs[0].0, "vex");
}

#[test]
fn graph_blocks_materialize_processor_results_on_first_access() {
    let graph = build_single_return_graph();

    assert!(
        graph
            .processor_outputs(ProcessorTarget::Block, 0x1000)
            .is_none()
    );

    let blocks = graph.blocks();
    assert_eq!(blocks.len(), 1);

    let outputs = graph
        .processor_outputs(ProcessorTarget::Block, 0x1000)
        .expect("block processor outputs should exist");
    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs[0].0, "vex");
}

#[test]
fn graph_mutation_invalidates_materialized_processor_results() {
    let mut graph = build_single_return_graph();

    let _ = graph.functions();
    assert!(
        graph
            .processor_outputs(ProcessorTarget::Function, 0x1000)
            .is_some()
    );

    let mut updated = graph
        .get_instruction(0x1000)
        .expect("instruction should still exist");
    updated.bytes = vec![0x90, 0xC3];
    updated.pattern = "90c3".to_string();
    graph.update_instruction(updated);

    assert!(
        graph
            .processor_outputs(ProcessorTarget::Function, 0x1000)
            .is_none()
    );

    let _ = graph.functions();
    assert!(
        graph
            .processor_outputs(ProcessorTarget::Function, 0x1000)
            .is_some()
    );
}

#[test]
fn graph_blocks_materialize_processor_results_via_configured_transport() {
    let graph = build_single_return_graph();

    let outputs = graph
        .blocks()
        .into_iter()
        .find(|block| block.address() == 0x1000)
        .and_then(|_| graph.processor_outputs(ProcessorTarget::Block, 0x1000))
        .expect("block processor outputs should exist");

    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs[0].0, "vex");
}

#[test]
fn live_entities_expose_processor_outputs() {
    let graph = build_single_return_graph();

    let instruction = graph
        .get_instruction(0x1000)
        .expect("instruction should exist");
    let instruction_outputs = instruction.processors();
    assert!(instruction_outputs.contains_key("vex"));
    assert_eq!(
        instruction.processor("vex"),
        instruction_outputs.get("vex").cloned().unwrap()
    );

    let block = graph
        .blocks()
        .into_iter()
        .find(|block| block.address() == 0x1000)
        .expect("block should exist");
    let block_outputs = block.processors();
    assert!(block_outputs.contains_key("vex"));
    assert_eq!(
        block.processor("vex"),
        block_outputs.get("vex").cloned().unwrap()
    );

    let function = graph
        .functions()
        .into_iter()
        .find(|function| function.address() == 0x1000)
        .expect("function should exist");
    let function_outputs = function.processors();
    assert!(function_outputs.contains_key("vex"));
    assert_eq!(
        function.processor("vex"),
        function_outputs.get("vex").cloned().unwrap()
    );
}
