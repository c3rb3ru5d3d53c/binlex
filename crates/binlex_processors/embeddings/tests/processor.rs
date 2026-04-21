use binlex::config::ConfigProcessor;
use binlex::controlflow::{Graph, Instruction};
use binlex::processor::GraphProcessor;
use binlex::runtime::Processor;
use binlex::{Architecture, Config};
use binlex_processor_embeddings::{EmbeddingsProcessor, EmbeddingsRequest, registration};

fn embeddings_config() -> Config {
    let mut config = Config::default();
    let default_config: ConfigProcessor = registration().default_config;
    config
        .processors
        .processors
        .insert("embeddings".to_string(), default_config);
    config
}

fn build_single_return_graph() -> Graph {
    let config = embeddings_config();
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
fn graph_options_enable_functions_and_blocks() {
    let options = <EmbeddingsProcessor as GraphProcessor>::on_graph_options();
    assert!(!options.instructions);
    assert!(!options.blocks);
    assert!(!options.functions);
}

#[test]
fn execute_returns_function_vectors() {
    let graph = build_single_return_graph();
    let request: EmbeddingsRequest = serde_json::from_value(serde_json::json!({
        "dimensions": 8,
        "device": "cpu",
        "threads": 1,
        "graph": graph.snapshot()
    }))
    .expect("request should deserialize");

    let response = EmbeddingsProcessor
        .execute(request)
        .expect("embeddings request should execute");

    let output = response
        .functions
        .get(&0x1000)
        .expect("function output should be present");
    let vector = output
        .get("vector")
        .and_then(serde_json::Value::as_array)
        .expect("function vector should be present");
    assert_eq!(vector.len(), 8);
}

#[test]
fn on_graph_returns_function_fanout() {
    let graph = build_single_return_graph();
    let fanout = <EmbeddingsProcessor as GraphProcessor>::on_graph(&graph)
        .expect("graph fanout should exist");

    let vector = fanout
        .functions
        .get(&0x1000)
        .and_then(|value| value.get("vector"))
        .and_then(|value| value.as_array())
        .expect("function vector should be present");
    assert_eq!(vector.len(), 64);
}
