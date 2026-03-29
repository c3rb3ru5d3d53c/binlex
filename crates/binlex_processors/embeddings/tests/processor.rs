use binlex::config::ConfigProcessor;
use binlex::controlflow::{Graph, Instruction};
use binlex::index::{Collection, LocalIndex};
use binlex::processor::GraphProcessor;
use binlex::runtime::Processor;
use binlex::{Architecture, Config};
use binlex_processor_embeddings::{
    EmbeddingsLocalIndexRequest, EmbeddingsProcessor, EmbeddingsRequest, registration,
};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

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
fn graph_options_enable_functions_only() {
    let options = <EmbeddingsProcessor as GraphProcessor>::on_graph_options();
    assert!(!options.instructions);
    assert!(!options.blocks);
    assert!(options.functions);
}

#[test]
fn execute_returns_function_vectors() {
    let request: EmbeddingsRequest = serde_json::from_value(serde_json::json!({
        "dimensions": 8,
        "device": "cpu",
        "threads": 1,
        "instructions": [],
        "blocks": [],
        "functions": [{
            "address": 0x1000u64,
            "data": {
                "type": "function",
                "address": 0x1000u64,
                "architecture": "amd64",
                "blocks": [0x1000u64],
                "number_of_instructions": 1,
                "number_of_blocks": 1,
                "cyclomatic_complexity": 0,
                "average_instructions_per_block": 1.0,
                "size": 1,
                "bytes": "c3",
                "contiguous": true,
                "cfg_blocks": [{
                    "address": 0x1000u64,
                    "chromosome": {
                        "pattern": "c3",
                        "mask": "00",
                        "entropy": 0.0,
                        "vector": [3]
                    },
                    "entropy": 0.0,
                    "size": 1,
                    "edges": 0,
                    "number_of_instructions": 1,
                    "call_count": 0,
                    "direct_call_count": 0,
                    "indirect_call_count": 0,
                    "conditional": false,
                    "is_return": true,
                    "is_trap": false,
                    "contiguous": true,
                    "next": null,
                    "to": [],
                    "blocks": []
                }]
            }
        }]
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

#[test]
fn complete_stage_indexes_function_vectors_locally() {
    let graph = build_single_return_graph();
    let fanout = <EmbeddingsProcessor as GraphProcessor>::on_graph(&graph)
        .expect("graph fanout should exist");

    let mut snapshot = graph.snapshot();
    snapshot.processor_outputs.functions = HashMap::from([(
        0x1000,
        vec![(
            "embeddings".to_string(),
            fanout
                .functions
                .get(&0x1000)
                .cloned()
                .expect("function embedding should exist"),
        )],
    )]);

    let root = std::env::temp_dir().join(format!(
        "binlex-embeddings-index-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic")
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).expect("temp index root should be created");

    let request = EmbeddingsRequest {
        stage: Some("complete".to_string()),
        dimensions: Some(64),
        device: Some("cpu".to_string()),
        threads: Some(1),
        snapshot: Some(snapshot),
        sha256: Some(
            "ae3f4619b0413d70d3004b9131c3752153074e45725be13b9a148978895e359e"
                .to_string(),
        ),
        corpora: vec!["default".to_string()],
        attributes: Vec::new(),
        index: Some(EmbeddingsLocalIndexRequest {
            enabled: true,
            path: root.to_string_lossy().into_owned(),
            selector: "processors.embeddings.vector".to_string(),
            corpus: "default".to_string(),
            function: true,
            block: false,
            instruction: false,
        }),
        instructions: Vec::new(),
        blocks: Vec::new(),
        functions: Vec::new(),
    };

    EmbeddingsProcessor
        .execute(request)
        .expect("complete request should index locally");

    let mut config = Config::default();
    config.index.local.directory = root.to_string_lossy().into_owned();
    config.index.local.dimensions = Some(64);
    let index = LocalIndex::new(config).expect("local index should open");
    let results = index
        .exact_search(
            &["default".to_string()],
            "ae3f4619b0413d70d3004b9131c3752153074e45725be13b9a148978895e359e",
            Some(&[Collection::Function]),
            &[],
            4,
        )
        .expect("exact search should succeed");
    assert_eq!(results.len(), 1);

    let _ = std::fs::remove_dir_all(root);
}
