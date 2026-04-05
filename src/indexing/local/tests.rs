use super::support::{digest_hex, embedding_id_for_vector, manual_object_id, selector_vector};
use super::*;
use crate::controlflow::{Function, Graph, Instruction};
use crate::databases::SampleStatus as DbSampleStatus;
use crate::formats::SymbolJson;
use crate::indexing::{Collection, Entity};
use crate::metadata::{Attribute, SymbolType};
use crate::{Architecture, Config};
use chrono::{TimeZone, Utc};
use serde_json::json;
use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

fn embeddings_processor_path(manifest_dir: &std::path::Path) -> PathBuf {
    let binary_name = if cfg!(windows) {
        "binlex-processor-embeddings.exe"
    } else {
        "binlex-processor-embeddings"
    };
    manifest_dir.join("target").join("debug").join(binary_name)
}

fn embeddings_processor_dir() -> String {
    static PROCESSOR_DIR: OnceLock<String> = OnceLock::new();

    PROCESSOR_DIR
        .get_or_init(|| {
            let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            let processor_path = embeddings_processor_path(&manifest_dir);
            if !processor_path.exists() {
                let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
                let mut command = Command::new(cargo);
                command.current_dir(&manifest_dir);
                command.env_remove("RUSTC_WRAPPER");
                if let Ok(rustc) = std::env::var("RUSTC") {
                    command.env("RUSTC", rustc);
                }
                command.args([
                    "build",
                    "-p",
                    "binlex-processor-embeddings",
                    "--bin",
                    "binlex-processor-embeddings",
                ]);
                let status = command
                    .status()
                    .expect("cargo should build binlex-processor-embeddings");
                assert!(
                    status.success(),
                    "binlex-processor-embeddings binary should build"
                );
            }

            processor_path
                .parent()
                .expect("processor binary should have a parent directory")
                .to_string_lossy()
                .into_owned()
        })
        .clone()
}

fn build_single_return_graph() -> Graph {
    let processor_dir = embeddings_processor_dir();
    let mut config = Config::default();
    config.processors.enabled = true;
    config.processors.path = Some(processor_dir);
    let embeddings = config
        .processors
        .ensure_processor("embeddings")
        .expect("embeddings processor config should exist");
    embeddings.enabled = true;
    embeddings.instructions.enabled = false;
    embeddings.blocks.enabled = false;
    embeddings.functions.enabled = false;
    embeddings.graph.enabled = true;
    embeddings.transport.ipc.enabled = true;
    embeddings.transport.http.enabled = false;
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

fn build_plain_single_return_graph() -> Graph {
    let config = Config::default();
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

fn symbol_attribute(name: &str, entity: Entity, address: u64) -> Attribute {
    Attribute::Symbol(SymbolJson {
        type_: "symbol".to_string(),
        symbol_type: match entity {
            Collection::Instruction => SymbolType::Instruction,
            Collection::Block => SymbolType::Block,
            Collection::Function => SymbolType::Function,
        }
        .to_string(),
        name: name.to_string(),
        address,
    })
}

fn test_vector(primary: usize) -> Vec<f32> {
    let mut vector = vec![0.0; 64];
    if primary < vector.len() {
        vector[primary] = 1.0;
    }
    vector
}

fn single_return_function() -> Function<'static> {
    let graph = Box::leak(Box::new(build_single_return_graph()));
    Function::new(0x1000, graph).expect("build function")
}

fn stage_vector_entry(
    client: &LocalIndex,
    corpora: &[String],
    collection: Entity,
    architecture: Architecture,
    vector: &[f32],
    sha256: &str,
    address: u64,
) {
    client
        .index_many(
            corpora,
            collection,
            architecture,
            "anonymous",
            vector,
            sha256,
            address,
            0,
            None,
            &[],
        )
        .expect("stage vector entry");
}

fn local_config_with_dimensions(root: &std::path::Path, dimensions: Option<usize>) -> Config {
    let mut config = Config::default();
    config.index.local.directory = root.to_string_lossy().into_owned();
    config.index.local.dimensions = dimensions;
    config
}

#[test]
fn manual_vector_index_round_trip() {
    let root = std::env::temp_dir().join(format!(
        "binlex-local-store-manual-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let client = LocalIndex::with_options(Config::default(), Some(root.clone()), None)
        .expect("create local index client");
    let graph = build_plain_single_return_graph();

    client
        .graph_many(&["corpus".to_string()], "deadbeef", &graph, &[], None, None)
        .expect("stage graph");
    stage_vector_entry(
        &client,
        &["corpus".to_string()],
        Entity::Function,
        Architecture::AMD64,
        &test_vector(0),
        "deadbeef",
        0x1000,
    );
    client.commit().expect("commit staged entries");

    let hits = client
        .nearest(
            &["corpus".to_string()],
            &test_vector(0),
            Some(&[Entity::Function]),
            &[Architecture::AMD64],
            4,
        )
        .expect("search local index");

    assert_eq!(hits.len(), 1);
    assert_eq!(
        hits[0].object_id(),
        manual_object_id(Entity::Function, "amd64", "deadbeef", 0x1000)
    );
    assert_eq!(hits[0].sha256(), "deadbeef");
    assert_eq!(hits[0].address(), 0x1000);

    let restored = client
        .sample_load("corpus", "deadbeef")
        .expect("restore graph");
    assert_eq!(restored.functions().len(), 1);

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn directional_compare_queries_return_compare_pairs() {
    let root = std::env::temp_dir().join(format!(
        "binlex-local-index-directional-compare-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let client = LocalIndex::with_options(Config::default(), Some(root.clone()), None)
        .expect("create local index client");

    stage_vector_entry(
        &client,
        &["malware".to_string()],
        Entity::Function,
        Architecture::AMD64,
        &test_vector(0),
        "left-sample",
        0x1000,
    );
    stage_vector_entry(
        &client,
        &["goodware".to_string()],
        Entity::Function,
        Architecture::AMD64,
        &test_vector(0),
        "right-sample",
        0x2000,
    );
    client.commit().expect("commit staged entries");

    let results = client
        .search(
            "corpus:malware AND collection:function -> corpus:goodware AND collection:function",
            10,
            1,
        )
        .expect("run compare query");

    assert_eq!(results.len(), 1);
    let lhs = results[0].lhs().expect("lhs result");
    let rhs = results[0].rhs().expect("rhs result");
    assert_eq!(lhs.sha256(), "left-sample");
    assert_eq!(rhs.sha256(), "right-sample");
    assert!(results[0].score() > 0.99);

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn directional_compare_queries_support_drop_projection() {
    let root = std::env::temp_dir().join(format!(
        "binlex-local-index-directional-drop-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let client = LocalIndex::with_options(Config::default(), Some(root.clone()), None)
        .expect("create local index client");

    stage_vector_entry(
        &client,
        &["malware".to_string()],
        Entity::Function,
        Architecture::AMD64,
        &test_vector(0),
        "left-sample",
        0x1000,
    );
    stage_vector_entry(
        &client,
        &["goodware".to_string()],
        Entity::Function,
        Architecture::AMD64,
        &test_vector(0),
        "right-sample",
        0x2000,
    );
    client.commit().expect("commit staged entries");

    let results = client
        .search(
            "(corpus:malware AND collection:function -> corpus:goodware AND collection:function) | drop:rhs",
            10,
            1,
        )
        .expect("run projected compare query");

    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0].lhs().expect("lhs result").sha256(),
        "left-sample"
    );
    assert!(results[0].rhs().is_none());

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn search_results_include_embedding_id_and_exact_count() {
    let root = std::env::temp_dir().join(format!(
        "binlex-local-store-embedding-count-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let client = LocalIndex::with_options(Config::default(), Some(root.clone()), None)
        .expect("create local index client");
    let graph = build_plain_single_return_graph();
    let shared_vector = test_vector(7);

    for sha256 in ["alpha-sha", "beta-sha", "gamma-sha", "delta-sha"] {
        client
            .graph_many(&["demo".to_string()], sha256, &graph, &[], None, None)
            .expect("stage graph");
    }
    stage_vector_entry(
        &client,
        &["demo".to_string()],
        Entity::Function,
        Architecture::AMD64,
        &shared_vector,
        "alpha-sha",
        0x1000,
    );
    stage_vector_entry(
        &client,
        &["demo".to_string()],
        Entity::Function,
        Architecture::AMD64,
        &shared_vector,
        "beta-sha",
        0x2000,
    );
    stage_vector_entry(
        &client,
        &["demo".to_string()],
        Entity::Block,
        Architecture::AMD64,
        &shared_vector,
        "gamma-sha",
        0x3000,
    );
    stage_vector_entry(
        &client,
        &["demo".to_string()],
        Entity::Function,
        Architecture::I386,
        &shared_vector,
        "delta-sha",
        0x4000,
    );
    client.commit().expect("commit entries");

    let hits = client
        .nearest(
            &["demo".to_string()],
            &shared_vector,
            Some(&[Entity::Function]),
            &[Architecture::AMD64],
            8,
        )
        .expect("search function embeddings");

    assert_eq!(hits.len(), 2);
    let expected_embedding = embedding_id_for_vector(&shared_vector);
    assert!(hits.iter().all(|hit| hit.embedding() == expected_embedding));
    assert!(hits.iter().all(|hit| hit.embeddings() == 2));

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn embedding_search_pivots_to_exact_vector_group() {
    let root = std::env::temp_dir().join(format!(
        "binlex-local-store-embedding-search-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let client = LocalIndex::with_options(Config::default(), Some(root.clone()), None)
        .expect("create local index client");
    let graph = build_plain_single_return_graph();
    let shared_vector = test_vector(9);

    for sha256 in ["alpha-sha", "beta-sha", "gamma-sha"] {
        client
            .graph_many(&["demo".to_string()], sha256, &graph, &[], None, None)
            .expect("stage graph");
    }
    stage_vector_entry(
        &client,
        &["demo".to_string()],
        Entity::Function,
        Architecture::AMD64,
        &shared_vector,
        "alpha-sha",
        0x1000,
    );
    stage_vector_entry(
        &client,
        &["demo".to_string()],
        Entity::Function,
        Architecture::AMD64,
        &shared_vector,
        "beta-sha",
        0x2000,
    );
    stage_vector_entry(
        &client,
        &["demo".to_string()],
        Entity::Function,
        Architecture::AMD64,
        &test_vector(10),
        "gamma-sha",
        0x3000,
    );
    client.commit().expect("commit entries");

    let embedding = embedding_id_for_vector(&shared_vector);
    let hits = client
        .embedding_search(
            &["demo".to_string()],
            &embedding,
            Some(&[Entity::Function]),
            &[Architecture::AMD64],
            8,
        )
        .expect("search by embedding");

    assert_eq!(hits.len(), 2);
    assert!(hits.iter().all(|hit| hit.embedding() == embedding));
    assert!(hits.iter().all(|hit| hit.embeddings() == 2));
    assert!(hits.iter().all(|hit| hit.collection() == Entity::Function));
    assert!(hits.iter().all(|hit| hit.architecture() == "amd64"));

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn selector_graph_round_trip() {
    let root = std::env::temp_dir().join(format!(
        "binlex-local-store-selector-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let graph = build_single_return_graph();
    let vector = {
        let functions = graph.functions();
        let processed = serde_json::to_value(functions[0].process()).expect("serialize function");
        selector_vector(&processed, "processors.embeddings.vector").expect("function vector")
    };
    let client = LocalIndex::with_options(Config::default(), Some(root.clone()), None)
        .expect("create local index client");

    client
        .graph_many(
            &["corpus".to_string()],
            "feedface",
            &graph,
            &[],
            Some("processors.embeddings.vector"),
            None,
        )
        .expect("stage graph with selector");
    client.commit().expect("commit staged graph");

    let hits = client
        .nearest(
            &["corpus".to_string()],
            &vector,
            Some(&[Entity::Function]),
            &[Architecture::AMD64],
            4,
        )
        .expect("search local index");

    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].sha256(), "feedface");
    assert_eq!(hits[0].address(), 0x1000);

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn function_results_persist_and_filter_structural_metrics() {
    let root = std::env::temp_dir().join(format!(
        "binlex-local-store-function-metrics-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let client = LocalIndex::with_options(Config::default(), Some(root.clone()), None)
        .expect("create local index client");
    let graph = build_single_return_graph();
    let function = Function::new(0x1000, &graph).expect("build function");
    let sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    client
        .graph_many(&["demo".to_string()], sha256, &graph, &[], None, None)
        .expect("stage graph");
    client
        .function_many(
            &["demo".to_string()],
            &function,
            &test_vector(0),
            sha256,
            &[],
        )
        .expect("stage function");
    client.commit().expect("commit function metrics");

    let hits = client
        .exact_search(
            &["demo".to_string()],
            sha256,
            Some(&[Entity::Function]),
            &[Architecture::AMD64],
            8,
        )
        .expect("exact search function");

    assert_eq!(hits.len(), 1);
    let hit = &hits[0];
    assert!(
        hit.cyclomatic_complexity().is_some(),
        "persist cyclomatic complexity"
    );
    assert!(
        hit.average_instructions_per_block().is_some(),
        "persist average instructions per block"
    );
    assert!(
        hit.number_of_instructions().is_some(),
        "persist instruction count"
    );
    assert!(hit.number_of_blocks().is_some(), "persist block count");
    assert!(hit.entropy().is_some(), "persist entropy");
    assert!(
        hit.chromosome_entropy().is_some(),
        "persist chromosome entropy"
    );
    assert_eq!(hit.contiguous(), Some(true));

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn search_merges_multiple_corpora_and_default_entities() {
    let root = std::env::temp_dir().join(format!(
        "binlex-local-store-search-merge-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let client = LocalIndex::with_options(Config::default(), Some(root.clone()), None)
        .expect("create local index client");

    stage_vector_entry(
        &client,
        &["alpha".to_string()],
        Entity::Function,
        Architecture::AMD64,
        &test_vector(0),
        "alpha-sha",
        0x1000,
    );
    stage_vector_entry(
        &client,
        &["beta".to_string()],
        Entity::Block,
        Architecture::AMD64,
        &test_vector(0),
        "beta-sha",
        0x2000,
    );
    client.commit().expect("commit staged vectors");

    let hits = client
        .nearest(
            &["alpha".to_string(), "beta".to_string()],
            &test_vector(0),
            None,
            &[Architecture::AMD64],
            8,
        )
        .expect("search local index");

    assert_eq!(hits.len(), 2);
    assert_eq!(hits[0].score(), 1.0);
    assert_eq!(hits[1].score(), 1.0);
    assert!(
        hits.iter()
            .any(|hit| hit.collection() == Entity::Function && hit.sha256() == "alpha-sha")
    );
    assert!(
        hits.iter()
            .any(|hit| hit.collection() == Entity::Block && hit.sha256() == "beta-sha")
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn shared_entries_support_multiple_corpora_without_duplicate_objects() {
    let root = std::env::temp_dir().join(format!(
        "binlex-local-store-shared-corpora-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let client = LocalIndex::with_options(Config::default(), Some(root.clone()), None)
        .expect("create local index client");
    let corpora = vec!["malware".to_string(), "plugx".to_string()];

    stage_vector_entry(
        &client,
        &corpora,
        Entity::Function,
        Architecture::AMD64,
        &test_vector(0),
        "shared-sha",
        0x1000,
    );
    client.commit().expect("commit shared vector");

    let keys = client
        .store
        .object_list("index/function/amd64/")
        .expect("list shared index entries");
    assert_eq!(keys.len(), 1);

    let hits = client
        .nearest(
            &["malware".to_string(), "plugx".to_string()],
            &test_vector(0),
            Some(&[Entity::Function]),
            &[Architecture::AMD64],
            8,
        )
        .expect("search shared object across corpora");
    assert_eq!(hits.len(), 1);
    assert_eq!(
        hits[0].corpora(),
        &["malware".to_string(), "plugx".to_string()]
    );

    client
        .sample_delete("malware", "shared-sha")
        .expect("delete malware membership");
    client.commit().expect("commit membership removal");

    let remaining_hits = client
        .nearest(
            &["malware".to_string(), "plugx".to_string()],
            &test_vector(0),
            Some(&[Entity::Function]),
            &[Architecture::AMD64],
            8,
        )
        .expect("search after one corpus removal");
    assert_eq!(remaining_hits.len(), 1);
    assert_eq!(remaining_hits[0].corpus(), "plugx");

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn uses_configured_directory_when_override_is_absent() {
    let root = std::env::temp_dir().join(format!(
        "binlex-local-store-config-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let mut config = Config::default();
    config.index.local.directory = root.to_string_lossy().into_owned();

    let client = LocalIndex::new(config).expect("create local index client");

    assert_eq!(client.store.root(), root.join("store"));
    assert_eq!(client.lancedb.root(), root.join("lancedb"));

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn repeat_graph_indexing_does_not_duplicate_search_results() {
    let root = std::env::temp_dir().join(format!(
        "binlex-local-store-repeat-index-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let client = LocalIndex::with_options(Config::default(), Some(root.clone()), None)
        .expect("create local index client");
    let graph = build_single_return_graph();
    let vector = {
        let functions = graph.functions();
        let processed = serde_json::to_value(functions[0].process()).expect("serialize function");
        selector_vector(&processed, "processors.embeddings.vector").expect("function vector")
    };

    for _ in 0..3 {
        client
            .graph(
                "repeat-sha",
                &graph,
                &[],
                Some("processors.embeddings.vector"),
                None,
            )
            .expect("stage graph with selector");
        client.commit().expect("commit repeated graph");
    }

    let hits = client
        .nearest(
            &["default".to_string()],
            &vector,
            Some(&[Entity::Function]),
            &[Architecture::AMD64],
            8,
        )
        .expect("search local index after repeat indexing");

    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].sha256(), "repeat-sha");
    assert_eq!(hits[0].address(), 0x1000);

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn search_results_expose_indexed_timestamp() {
    let root = std::env::temp_dir().join(format!(
        "binlex-local-store-indexed-timestamp-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let client = LocalIndex::with_options(Config::default(), Some(root.clone()), None)
        .expect("create local index client");

    stage_vector_entry(
        &client,
        &["demo".to_string()],
        Entity::Function,
        Architecture::AMD64,
        &test_vector(0),
        "dated-sha",
        0x1000,
    );
    client.commit().expect("commit vector");

    let hits = client
        .nearest(
            &["demo".to_string()],
            &test_vector(0),
            Some(&[Entity::Function]),
            &[Architecture::AMD64],
            4,
        )
        .expect("search dated result");

    assert_eq!(hits.len(), 1);
    assert!(hits[0].timestamp() > Utc.timestamp_opt(0, 0).single().unwrap());

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn add_remove_replace_symbol_updates_results() {
    let root = std::env::temp_dir().join(format!(
        "binlex-local-store-symbol-mutation-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let client = LocalIndex::with_options(Config::default(), Some(root.clone()), None)
        .expect("create local index client");

    client.sample_put(b"sample-bytes").expect("store sample");
    let function = single_return_function();
    client
        .function_many(
            &["demo".to_string()],
            &function,
            &test_vector(0),
            &digest_hex(b"sample-bytes"),
            &[symbol_attribute("alpha", Entity::Function, 0x1000)],
        )
        .expect("stage function");
    client.commit().expect("commit function");

    client
        .symbol_add(
            &digest_hex(b"sample-bytes"),
            crate::indexing::Collection::Function,
            0x1000,
            "beta",
        )
        .expect("add symbol");
    let add_hits = client
        .exact_search(
            &["demo".to_string()],
            &digest_hex(b"sample-bytes"),
            Some(&[Entity::Function]),
            &[Architecture::AMD64],
            8,
        )
        .expect("search symbols after add");
    assert_eq!(add_hits.len(), 2);
    assert!(add_hits.iter().any(|hit| hit.symbol() == Some("alpha")));
    assert!(add_hits.iter().any(|hit| hit.symbol() == Some("beta")));

    client
        .symbol_remove(
            &digest_hex(b"sample-bytes"),
            crate::indexing::Collection::Function,
            0x1000,
            "alpha",
        )
        .expect("remove symbol");
    let remove_hits = client
        .exact_search(
            &["demo".to_string()],
            &digest_hex(b"sample-bytes"),
            Some(&[Entity::Function]),
            &[Architecture::AMD64],
            8,
        )
        .expect("search symbols after remove");
    assert_eq!(remove_hits.len(), 1);
    assert_eq!(remove_hits[0].symbol(), Some("beta"));

    client
        .symbol_replace(
            &digest_hex(b"sample-bytes"),
            crate::indexing::Collection::Function,
            0x1000,
            "gamma",
        )
        .expect("replace symbol");
    let replace_hits = client
        .exact_search(
            &["demo".to_string()],
            &digest_hex(b"sample-bytes"),
            Some(&[Entity::Function]),
            &[Architecture::AMD64],
            8,
        )
        .expect("search symbols after replace");
    assert_eq!(replace_hits.len(), 1);
    assert_eq!(replace_hits[0].symbol(), Some("gamma"));

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn query_supports_pagination() {
    let root = std::env::temp_dir().join(format!(
        "binlex-local-store-query-pagination-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let client = LocalIndex::with_options(Config::default(), Some(root.clone()), None)
        .expect("create local index client");

    client.sample_put(b"first").expect("store first sample");
    client.sample_put(b"second").expect("store second sample");
    let function = single_return_function();
    client
        .function_many(
            &["demo".to_string()],
            &function,
            &test_vector(0),
            &digest_hex(b"first"),
            &[],
        )
        .expect("stage first function");
    client
        .function_many(
            &["demo".to_string()],
            &function,
            &test_vector(1),
            &digest_hex(b"second"),
            &[],
        )
        .expect("stage second function");
    client.commit().expect("commit functions");

    let page_one = client
        .search("collection:function", 1, 1)
        .expect("query first page");
    let page_two = client
        .search("collection:function", 1, 2)
        .expect("query second page");

    assert_eq!(page_one.len(), 1);
    assert_eq!(page_two.len(), 1);
    assert_ne!(page_one[0].sha256(), page_two[0].sha256());

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn query_filters_by_entity_size() {
    let root = std::env::temp_dir().join(format!(
        "binlex-local-store-size-query-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let client = LocalIndex::with_options(Config::default(), Some(root.clone()), None)
        .expect("create local index client");
    let sha256 = client.sample_put(b"size-sample").expect("store sample");
    let function = single_return_function();
    client
        .function(&function, &test_vector(0), &sha256, &[])
        .expect("stage function");
    client.commit().expect("commit function");

    let all_hits = client
        .search("collection:function", 8, 1)
        .expect("query functions");
    assert_eq!(all_hits.len(), 1);
    assert_eq!(all_hits[0].size(), 1);

    let sized_hits = client
        .search("size:1 AND collection:function", 8, 1)
        .expect("query size match");
    assert_eq!(sized_hits.len(), 1);
    assert_eq!(sized_hits[0].size(), 1);

    let empty_hits = client
        .search("size:>1 AND collection:function", 8, 1)
        .expect("query size mismatch");
    assert!(empty_hits.is_empty());

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn graph_level_corpus_mutations_recompute_inherited_entity_corpora() {
    let root = std::env::temp_dir().join(format!(
        "binlex-local-store-corpus-mutation-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let client = LocalIndex::with_options(Config::default(), Some(root.clone()), None)
        .expect("create local index client");

    let sha256 = client.sample_put(b"corpus-sample").expect("store sample");
    let graph = build_single_return_graph();
    client
        .graph_many(&["default".to_string()], &sha256, &graph, &[], None, None)
        .expect("stage graph metadata");
    stage_vector_entry(
        &client,
        &["default".to_string()],
        Entity::Function,
        Architecture::AMD64,
        &test_vector(0),
        &sha256,
        0x1000,
    );
    client.commit().expect("commit function");

    client
        .collection_corpus_add(&sha256, Entity::Function, "amd64", 0x1000, "malware")
        .expect("add corpus");
    let corpora = client.corpus_list().expect("list corpora after add");
    assert!(corpora.iter().any(|corpus| corpus == "default"));
    assert!(corpora.iter().any(|corpus| corpus == "malware"));
    let add_hits = client
        .search("corpus:malware AND collection:function", 8, 1)
        .expect("query after add corpus");
    assert_eq!(add_hits.len(), 1);
    assert_eq!(
        add_hits[0].corpora(),
        &["default".to_string(), "malware".to_string()]
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn entity_corpora_are_collection_scoped() {
    let root = std::env::temp_dir().join(format!(
        "binlex-local-store-collection-corpora-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let client = LocalIndex::with_options(Config::default(), Some(root.clone()), None)
        .expect("create local index client");

    let sha256 = client
        .sample_put(b"collection-corpora-sample")
        .expect("store sample");
    let graph = build_single_return_graph();
    client
        .graph_many(&["malware".to_string()], &sha256, &graph, &[], None, None)
        .expect("stage graph metadata");
    stage_vector_entry(
        &client,
        &["malware".to_string()],
        Entity::Function,
        Architecture::AMD64,
        &test_vector(0),
        &sha256,
        0x1000,
    );
    stage_vector_entry(
        &client,
        &["malware".to_string()],
        Entity::Block,
        Architecture::AMD64,
        &test_vector(1),
        &sha256,
        0x1000,
    );
    stage_vector_entry(
        &client,
        &["malware".to_string()],
        Entity::Instruction,
        Architecture::AMD64,
        &test_vector(2),
        &sha256,
        0x1000,
    );
    client.commit().expect("commit inherited entries");

    assert_eq!(
        client
            .search("corpus:malware AND collection:function", 8, 1)
            .expect("query inherited function")
            .len(),
        1
    );
    assert_eq!(
        client
            .search("corpus:malware AND collection:block", 8, 1)
            .expect("query block")
            .len(),
        1
    );
    assert_eq!(
        client
            .search("corpus:malware AND collection:instruction", 8, 1)
            .expect("query instruction")
            .len(),
        1
    );

    client
        .collection_corpus_add(&sha256, Entity::Function, "amd64", 0x1000, "goodware")
        .expect("add function corpus");

    assert_eq!(
        client
            .search("corpus:goodware AND collection:function", 8, 1)
            .expect("query function corpus")
            .len(),
        1
    );
    assert!(
        client
            .search("corpus:goodware AND collection:block", 8, 1)
            .expect("query block remains unchanged")
            .is_empty()
    );
    assert!(
        client
            .search("corpus:goodware AND collection:instruction", 8, 1)
            .expect("query instruction remains unchanged")
            .is_empty()
    );

    client
        .collection_corpus_add(&sha256, Entity::Block, "amd64", 0x1000, "clean")
        .expect("add block corpus");

    assert_eq!(
        client
            .search("corpus:goodware AND collection:function", 8, 1)
            .expect("function remains scoped")
            .len(),
        1
    );
    assert_eq!(
        client
            .search("corpus:clean AND collection:block", 8, 1)
            .expect("query overridden block")
            .len(),
        1
    );
    assert!(
        client
            .search("corpus:clean AND collection:instruction", 8, 1)
            .expect("instruction remains scoped")
            .is_empty()
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn localdb_metadata_round_trips_through_local_index() {
    let root = std::env::temp_dir().join(format!(
        "binlex-local-index-localdb-metadata-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let client = LocalIndex::with_options(Config::default(), Some(root.clone()), None)
        .expect("create local index client");

    let sha256 = client.sample_put(b"metadata-sample").expect("store sample");

    client.sample_tag_add(&sha256, "family").expect("add tag");
    client
        .sample_tag_add(&sha256, "malware")
        .expect("add second tag");
    let tags = client.sample_tag_search("mal", 1, 10).expect("search tags");
    assert_eq!(tags.items.len(), 1);
    assert_eq!(tags.items[0].tag, "malware");

    client
        .sample_tag_replace(&sha256, &["clean".to_string(), "training".to_string()])
        .expect("replace tags");
    let tags = client
        .sample_tag_search("tr", 1, 10)
        .expect("search replaced tags");
    assert_eq!(tags.items.len(), 1);
    assert_eq!(tags.items[0].tag, "training");
    client
        .sample_tag_remove(&sha256, "clean")
        .expect("remove tag");

    let function = single_return_function();
    client
        .function_many(
            &["default".to_string()],
            &function,
            &test_vector(7),
            &sha256,
            &[],
        )
        .expect("stage function for tag metadata");
    client.commit().expect("commit function for tag metadata");

    client
        .collection_tag_add(&sha256, Collection::Function, 0x1000, "goodware")
        .expect("add collection tag");
    let collection_tags = client
        .collection_tag_search("good", Some(Collection::Function), 1, 10)
        .expect("search collection tags");
    assert_eq!(collection_tags.items.len(), 1);
    assert_eq!(collection_tags.items[0].tag, "goodware");

    client
        .collection_tag_replace(
            &sha256,
            Collection::Function,
            0x1000,
            &["library".to_string(), "shared".to_string()],
        )
        .expect("replace collection tags");
    let collection_tags = client
        .collection_tag_search("shared", Some(Collection::Function), 1, 10)
        .expect("search replaced collection tags");
    assert_eq!(collection_tags.items.len(), 1);
    assert_eq!(collection_tags.items[0].tag, "shared");
    client
        .collection_tag_remove(&sha256, Collection::Function, 0x1000, "library")
        .expect("remove collection tag");

    client
        .sample_comment_add(&sha256, "needs review", None)
        .expect("add comment");
    client
        .sample_comment_add(&sha256, "interesting family overlap", None)
        .expect("add second comment");
    let comments = client
        .sample_comment_search("review", 1, 10)
        .expect("search comments");
    assert_eq!(comments.items.len(), 1);
    assert_eq!(comments.items[0].comment, "needs review");
    client
        .sample_comment_remove(&sha256, "needs review")
        .expect("remove comment");
    client
        .sample_comment_replace(
            &sha256,
            &["reviewed".to_string(), "shared code".to_string()],
            None,
        )
        .expect("replace comments");
    let comments = client
        .sample_comment_search("shared", 1, 10)
        .expect("search replaced comments");
    assert_eq!(comments.items.len(), 1);
    assert_eq!(comments.items[0].comment, "shared code");

    client
        .collection_comment_add(
            &sha256,
            Collection::Function,
            0x1000,
            "likely library",
            None,
        )
        .expect("add collection comment");
    let collection_comments = client
        .collection_comment_search("library", Some(Collection::Function), 1, 10)
        .expect("search collection comments");
    assert_eq!(collection_comments.items.len(), 1);
    assert_eq!(collection_comments.items[0].comment, "likely library");
    client
        .collection_comment_replace(
            &sha256,
            Collection::Function,
            0x1000,
            &["crt".to_string(), "shared".to_string()],
            None,
        )
        .expect("replace collection comments");
    let collection_comments = client
        .collection_comment_search("shared", Some(Collection::Function), 1, 10)
        .expect("search replaced collection comments");
    assert_eq!(collection_comments.items.len(), 1);
    assert_eq!(collection_comments.items[0].comment, "shared");
    client
        .collection_comment_remove(&sha256, Collection::Function, 0x1000, "crt")
        .expect("remove collection comment");

    client
        .sample_status_set(
            &sha256,
            DbSampleStatus::Processing,
            None,
            Some("req_local_index"),
            None,
        )
        .expect("set sample status");
    let status = client
        .sample_status_get(&sha256)
        .expect("get sample status")
        .expect("status present");
    assert_eq!(status.status, DbSampleStatus::Processing);
    assert_eq!(status.id.as_deref(), Some("req_local_index"));
    assert!(!status.timestamp.is_empty());
    client
        .sample_status_delete(&sha256)
        .expect("remove sample status");
    assert!(
        client
            .sample_status_get(&sha256)
            .expect("get deleted sample status")
            .is_none()
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn entity_tags_are_collection_scoped() {
    let root = std::env::temp_dir().join(format!(
        "binlex-local-index-effective-tags-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let client = LocalIndex::with_options(Config::default(), Some(root.clone()), None)
        .expect("create local index client");

    let sha256 = client.sample_put(b"tagged-graph").expect("store sample");
    let graph = build_plain_single_return_graph();
    client
        .graph_many(&["default".to_string()], &sha256, &graph, &[], None, None)
        .expect("store graph");
    let function = Function::new(0x1000, &graph).expect("build function");
    let block = function.blocks()[0].clone();
    let instruction = block.instructions()[0].clone();
    client
        .function_many(
            &["default".to_string()],
            &function,
            &test_vector(8),
            &sha256,
            &[],
        )
        .expect("index function");
    client
        .block_many(
            &["default".to_string()],
            &block,
            &test_vector(9),
            &sha256,
            &[],
        )
        .expect("index block");
    client
        .instruction_many(
            &["default".to_string()],
            &instruction,
            &test_vector(10),
            &sha256,
            &[],
        )
        .expect("index instruction");
    client.commit().expect("commit graph");

    client
        .collection_tag_add(&sha256, Collection::Function, 0x1000, "function")
        .expect("add function tag");
    client
        .collection_tag_add(&sha256, Collection::Block, 0x1000, "block")
        .expect("add block tag");
    client
        .collection_tag_add(&sha256, Collection::Instruction, 0x1000, "instruction")
        .expect("add instruction tag");

    assert_eq!(
        client
            .collection_tag_list(&sha256, Collection::Function, 0x1000)
            .expect("function tags"),
        vec!["function".to_string()]
    );
    assert_eq!(
        client
            .collection_tag_list(&sha256, Collection::Block, 0x1000)
            .expect("block tags"),
        vec!["block".to_string()]
    );
    assert_eq!(
        client
            .collection_tag_list(&sha256, Collection::Instruction, 0x1000)
            .expect("instruction tags"),
        vec!["instruction".to_string()]
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn rename_corpus_updates_index_globally() {
    let root = std::env::temp_dir().join(format!(
        "binlex-local-store-corpus-rename-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let client = LocalIndex::with_options(Config::default(), Some(root.clone()), None)
        .expect("create local index client");

    let first = client
        .sample_put(b"first-corpus")
        .expect("store first sample");
    let second = client
        .sample_put(b"second-corpus")
        .expect("store second sample");
    let function = single_return_function();
    client
        .function_many(
            &["malware".to_string()],
            &function,
            &test_vector(0),
            &first,
            &[],
        )
        .expect("stage first function");
    client
        .function_many(
            &["malware".to_string()],
            &function,
            &test_vector(1),
            &second,
            &[],
        )
        .expect("stage second function");
    client.commit().expect("commit functions");

    client
        .corpus_rename("malware", "malware-renamed")
        .expect("rename corpus");

    let corpora = client.corpus_list().expect("list corpora");
    assert!(corpora.iter().any(|corpus| corpus == "malware-renamed"));
    assert!(!corpora.iter().any(|corpus| corpus == "malware"));

    let hits = client
        .search("collection:function", 8, 1)
        .expect("query after rename corpus");
    assert_eq!(hits.len(), 2);
    assert!(hits.iter().all(|hit| {
        hit.corpora()
            .iter()
            .any(|corpus| corpus == "malware-renamed")
    }));
    assert!(
        !hits
            .iter()
            .any(|hit| hit.corpora().iter().any(|corpus| corpus == "malware"))
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn reindex_updates_result_timestamp() {
    let root = std::env::temp_dir().join(format!(
        "binlex-local-store-reindex-timestamp-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let client = LocalIndex::with_options(Config::default(), Some(root.clone()), None)
        .expect("create local index client");

    stage_vector_entry(
        &client,
        &["demo".to_string()],
        Entity::Function,
        Architecture::AMD64,
        &test_vector(0),
        "dated-sha",
        0x1000,
    );
    client.commit().expect("commit first vector");

    let first_date = client
        .nearest(
            &["demo".to_string()],
            &test_vector(0),
            Some(&[Entity::Function]),
            &[Architecture::AMD64],
            4,
        )
        .expect("search first dated result")[0]
        .timestamp();

    std::thread::sleep(std::time::Duration::from_secs(1));

    stage_vector_entry(
        &client,
        &["demo".to_string()],
        Entity::Function,
        Architecture::AMD64,
        &test_vector(0),
        "dated-sha",
        0x1000,
    );
    client.commit().expect("commit second vector");

    let second_date = client
        .nearest(
            &["demo".to_string()],
            &test_vector(0),
            Some(&[Entity::Function]),
            &[Architecture::AMD64],
            4,
        )
        .expect("search second dated result")[0]
        .timestamp();

    assert!(second_date > first_date);

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn same_corpus_distinct_symbols_expand_flat_results_without_duplicate_objects() {
    let root = std::env::temp_dir().join(format!(
        "binlex-local-store-symbols-same-corpus-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let client = LocalIndex::with_options(Config::default(), Some(root.clone()), None)
        .expect("create local index client");
    let function = single_return_function();

    client
        .function_many(
            &["alpha".to_string()],
            &function,
            &test_vector(0),
            "alpha-sha",
            &[symbol_attribute("malware_steal", Entity::Function, 0x1000)],
        )
        .expect("stage first symbol");
    client.commit().expect("commit first symbol");

    client
        .function_many(
            &["alpha".to_string()],
            &function,
            &test_vector(1),
            "alpha-sha",
            &[symbol_attribute(
                "malware_stealer",
                Entity::Function,
                0x1000,
            )],
        )
        .expect("stage second symbol");
    client.commit().expect("commit second symbol");

    let keys = client
        .store
        .object_list("index/function/amd64/")
        .expect("list canonical function entries");
    assert_eq!(keys.len(), 1);

    let hits = client
        .nearest(
            &["alpha".to_string()],
            &test_vector(1),
            Some(&[Entity::Function]),
            &[Architecture::AMD64],
            8,
        )
        .expect("search same-corpus symbols");
    assert_eq!(hits.len(), 2);
    assert!(
        hits.iter()
            .all(|hit| hit.corpora().iter().any(|corpus| corpus == "alpha"))
    );
    assert!(hits.iter().any(|hit| hit.symbol() == Some("malware_steal")));
    assert!(
        hits.iter()
            .any(|hit| hit.symbol() == Some("malware_stealer"))
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn cross_corpus_symbols_expand_flat_results_per_corpus() {
    let root = std::env::temp_dir().join(format!(
        "binlex-local-store-symbols-cross-corpus-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let client = LocalIndex::with_options(Config::default(), Some(root.clone()), None)
        .expect("create local index client");
    let function = single_return_function();

    client
        .function_many(
            &["person_a".to_string()],
            &function,
            &test_vector(0),
            "shared-sha",
            &[symbol_attribute("malware_steal", Entity::Function, 0x1000)],
        )
        .expect("stage corpus a symbol");
    client.commit().expect("commit corpus a symbol");

    client
        .function_many(
            &["person_b".to_string()],
            &function,
            &test_vector(0),
            "shared-sha",
            &[symbol_attribute(
                "malware_stealer",
                Entity::Function,
                0x1000,
            )],
        )
        .expect("stage corpus b symbol");
    client.commit().expect("commit corpus b symbol");

    let hits = client
        .nearest(
            &["person_a".to_string(), "person_b".to_string()],
            &test_vector(0),
            Some(&[Entity::Function]),
            &[Architecture::AMD64],
            8,
        )
        .expect("search cross-corpus symbols");
    assert_eq!(hits.len(), 2);
    assert!(hits.iter().all(|hit| {
        hit.corpora().iter().any(|corpus| corpus == "person_a")
            && hit.corpora().iter().any(|corpus| corpus == "person_b")
    }));
    assert!(hits.iter().any(|hit| hit.symbol() == Some("malware_steal")));
    assert!(
        hits.iter()
            .any(|hit| hit.symbol() == Some("malware_stealer"))
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn explicit_directory_overrides_configured_directory() {
    let configured_root = std::env::temp_dir().join(format!(
        "binlex-local-store-configured-test-{}",
        std::process::id()
    ));
    let override_root = std::env::temp_dir().join(format!(
        "binlex-local-store-override-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&configured_root);
    let _ = std::fs::remove_dir_all(&override_root);
    let mut config = Config::default();
    config.index.local.directory = configured_root.to_string_lossy().into_owned();

    let client = LocalIndex::with_options(config, Some(override_root.clone()), None)
        .expect("create local index client");

    assert_eq!(client.store.root(), override_root.join("store"));
    assert_eq!(client.lancedb.root(), override_root.join("lancedb"));
    assert!(!configured_root.exists());

    let _ = std::fs::remove_dir_all(&configured_root);
    let _ = std::fs::remove_dir_all(&override_root);
}

#[test]
fn rejects_manual_vector_with_wrong_configured_dimensions() {
    let root = std::env::temp_dir().join(format!(
        "binlex-local-store-dims-write-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let client = LocalIndex::new(local_config_with_dimensions(&root, Some(4)))
        .expect("create local index client");

    let error = client
        .index_many(
            &["demo".to_string()],
            Entity::Function,
            Architecture::AMD64,
            "anonymous",
            &test_vector(0),
            "deadbeef",
            0x1000,
            0,
            None,
            &[],
        )
        .expect_err("reject wrong vector length");

    assert_eq!(
        error.to_string(),
        "local index configuration error: vector length 64 does not match configured index.local.dimensions 4"
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn rejects_search_vector_with_wrong_configured_dimensions() {
    let root = std::env::temp_dir().join(format!(
        "binlex-local-store-dims-search-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let client = LocalIndex::new(local_config_with_dimensions(&root, Some(4)))
        .expect("create local index client");

    let error = client
        .nearest(
            &["demo".to_string()],
            &[1.0, 0.0, 0.0],
            Some(&[Entity::Function]),
            &[Architecture::AMD64],
            4,
        )
        .expect_err("reject wrong search vector length");

    assert_eq!(
        error.to_string(),
        "local index configuration error: vector length 3 does not match configured index.local.dimensions 4"
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn rejects_selector_vectors_with_wrong_configured_dimensions() {
    let root = std::env::temp_dir().join(format!(
        "binlex-local-store-dims-selector-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let graph = build_single_return_graph();
    let client = LocalIndex::new(local_config_with_dimensions(&root, Some(8)))
        .expect("create local index client");

    let error = client
        .graph_many(
            &["demo".to_string()],
            "feedface",
            &graph,
            &[],
            Some("processors.embeddings.vector"),
            None,
        )
        .expect_err("reject selector vector length mismatch");

    assert!(
        error
            .to_string()
            .contains("does not match configured index.local.dimensions 8")
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn rejects_existing_table_dimension_mismatch_on_open() {
    let root = std::env::temp_dir().join(format!(
        "binlex-local-store-dims-existing-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);

    let writer = LocalIndex::new(local_config_with_dimensions(&root, Some(3)))
        .expect("create local index writer");
    writer
        .index_many(
            &["demo".to_string()],
            Entity::Function,
            Architecture::AMD64,
            "anonymous",
            &[1.0, 0.0, 0.0],
            "deadbeef",
            0x1000,
            0,
            None,
            &[],
        )
        .expect("stage vector");
    writer.commit().expect("commit vector");

    let error = match LocalIndex::new(local_config_with_dimensions(&root, Some(4))) {
        Ok(_) => panic!("reject existing table dimension mismatch"),
        Err(error) => error,
    };

    assert!(
            error
                .to_string()
                .contains("existing local index table function__amd64 uses dimensions 3, but index.local.dimensions is 4")
        );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn selector_vector_supports_bracket_array_indexing() {
    let value = json!({
        "thing": {
            "items": [
                { "vector": [1.0, 2.0, 3.0] },
                { "vector": [4.0, 5.0, 6.0] }
            ]
        }
    });

    assert_eq!(
        selector_vector(&value, "thing.items[0].vector"),
        Some(vec![1.0, 2.0, 3.0])
    );
    assert_eq!(
        selector_vector(&value, "thing.items[1].vector"),
        Some(vec![4.0, 5.0, 6.0])
    );
}

#[test]
fn selector_vector_rejects_invalid_bracket_array_indexing() {
    let value = json!({
        "thing": {
            "items": [
                { "vector": [1.0, 2.0, 3.0] }
            ]
        }
    });

    assert_eq!(selector_vector(&value, "thing.items[].vector"), None);
    assert_eq!(selector_vector(&value, "thing.items[abc].vector"), None);
    assert_eq!(selector_vector(&value, "thing.items[2].vector"), None);
    assert_eq!(selector_vector(&value, "thing.items[0"), None);
}
