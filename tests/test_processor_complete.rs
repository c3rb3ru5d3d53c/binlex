#![cfg(not(target_os = "windows"))]

use binlex::controlflow::{Graph, Instruction};
use binlex::{Architecture, Config};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

fn processor_dir() -> String {
    static PROCESSOR_DIR: OnceLock<String> = OnceLock::new();

    PROCESSOR_DIR
        .get_or_init(|| {
            let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            let target_dir = manifest_dir.join("target").join("debug");
            let vex_path = target_dir.join("binlex-processor-vex");
            let complete_path = target_dir.join("binlex-processor-complete-test");
            if vex_path.exists() && complete_path.exists() {
                return target_dir.to_string_lossy().into_owned();
            }

            let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
            let vex_status = Command::new(&cargo)
                .current_dir(&manifest_dir)
                .args([
                    "build",
                    "-p",
                    "binlex-processor-vex",
                    "--bin",
                    "binlex-processor-vex",
                    "--target-dir",
                    target_dir
                        .to_str()
                        .expect("target dir path should be valid"),
                ])
                .status()
                .expect("cargo should build binlex-processor-vex");
            assert!(vex_status.success(), "binlex-processor-vex binary should build");

            let complete_status = Command::new(&cargo)
                .current_dir(&manifest_dir)
                .args([
                    "build",
                    "-p",
                    "binlex-processor-complete-test",
                    "--bin",
                    "binlex-processor-complete-test",
                    "--target-dir",
                    target_dir
                        .to_str()
                        .expect("target dir path should be valid"),
                ])
                .status()
                .expect("cargo should build binlex-processor-complete-test");
            assert!(
                complete_status.success(),
                "binlex-processor-complete-test binary should build"
            );

            target_dir.to_string_lossy().into_owned()
        })
        .clone()
}

fn output_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "binlex-{}-{}-{}.jsonl",
        name,
        std::process::id(),
        std::thread::current().name().unwrap_or("main")
    ))
}

fn test_config(path: &Path, enable_vex: bool) -> Config {
    let mut config = Config::default();
    config.processors.enabled = true;
    config.processors.path = Some(processor_dir());
    config.processors.processes = 1;
    config.processors.compression = true;
    for processor in config.processors.processors.values_mut() {
        processor.enabled = false;
        processor.instructions.enabled = false;
        processor.blocks.enabled = false;
        processor.functions.enabled = false;
        processor.graph.enabled = false;
        processor.complete.enabled = false;
    }

    let complete = config
        .processors
        .ensure_processor("complete-test")
        .expect("complete-test processor config should exist");
    complete.enabled = true;
    complete.complete.enabled = true;
    complete.options.insert(
        "path".to_string(),
        path.to_string_lossy().into_owned().into(),
    );

    if enable_vex {
        let vex = config
            .processors
            .ensure_processor("vex")
            .expect("vex processor config should exist");
        vex.enabled = true;
        vex.functions.enabled = true;
    }

    config
}

fn build_single_return_graph(config: Config) -> Graph {
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

fn read_json_lines(path: &Path) -> Vec<Value> {
    fs::read_to_string(path)
        .expect("completion output file should exist")
        .lines()
        .map(|line| serde_json::from_str(line).expect("json line should parse"))
        .collect()
}

#[test]
fn process_complete_persists_finalized_outputs() {
    let path = output_path("complete-persist");
    let _ = fs::remove_file(&path);
    let graph = build_single_return_graph(test_config(&path, true));

    graph
        .process_complete()
        .expect("completion processing should succeed");

    let lines = read_json_lines(&path);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["stage"], "complete");
    assert_eq!(lines[0]["instruction_count"], 1);
    assert_eq!(lines[0]["block_count"], 1);
    assert_eq!(lines[0]["function_count"], 1);
    assert_eq!(lines[0]["vex_functions"], 1);

    let _ = fs::remove_file(path);
}

#[test]
fn entity_access_does_not_trigger_completion_side_effects() {
    let path = output_path("complete-lazy");
    let _ = fs::remove_file(&path);
    let graph = build_single_return_graph(test_config(&path, false));

    let _ = graph.blocks();
    let _ = graph.functions();

    assert!(!path.exists(), "completion should not run on entity access");

    graph
        .process_complete()
        .expect("completion processing should succeed");

    assert!(path.exists(), "explicit completion should persist output");
    let _ = fs::remove_file(path);
}

#[test]
fn completion_runs_once_per_revision_and_replays_after_mutation() {
    let path = output_path("complete-revision");
    let _ = fs::remove_file(&path);
    let mut graph = build_single_return_graph(test_config(&path, false));

    graph
        .process_complete()
        .expect("initial completion processing should succeed");
    graph
        .process_complete()
        .expect("cached completion processing should succeed");
    assert_eq!(read_json_lines(&path).len(), 1);

    let mut updated = graph
        .get_instruction(0x1000)
        .expect("instruction should still exist");
    updated.bytes = vec![0x90, 0xC3];
    updated.pattern = "90c3".to_string();
    graph.update_instruction(updated);

    graph
        .process_complete()
        .expect("completion processing after mutation should succeed");
    assert_eq!(read_json_lines(&path).len(), 2);

    let _ = fs::remove_file(path);
}
