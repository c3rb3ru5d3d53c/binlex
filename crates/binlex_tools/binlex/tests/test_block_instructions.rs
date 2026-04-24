#![cfg(not(target_os = "windows"))]

use binlex::Config;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn temp_path(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be valid")
        .as_nanos();
    std::env::temp_dir().join(format!("binlex-{name}-{nanos}-{}", std::process::id()))
}

fn command_with_temp_config(binary: &PathBuf, config_home: &PathBuf) -> Command {
    let mut command = Command::new(binary);
    command.env("XDG_CONFIG_HOME", config_home);
    command
}

fn binlex_binary() -> PathBuf {
    static BINLEX_PATH: OnceLock<PathBuf> = OnceLock::new();

    BINLEX_PATH
        .get_or_init(|| {
            let workspace_root = workspace_root();
            let binary_path = workspace_root.join("target").join("debug").join("binlex");
            if binary_path.exists() {
                return binary_path;
            }

            let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
            let mut command = Command::new(cargo);
            command.current_dir(&workspace_root);
            if let Ok(rustc) = std::env::var("RUSTC") {
                command.env("RUSTC", rustc);
            }
            let status = command
                .args(["build", "-p", "binlex-cli", "--bin", "binlex"])
                .status()
                .expect("cargo should build the binlex binary");
            assert!(status.success(), "binlex binary should build");
            binary_path
        })
        .clone()
}

#[test]
fn test_block_instructions_are_emitted_as_addresses() {
    let binlex = binlex_binary();
    let input_path = temp_path("input.bin");
    let output_path = temp_path("output.jsonl");
    let config_home = temp_path("config-home");

    fs::write(&input_path, [0xC3]).expect("input file should be written");

    let status = command_with_temp_config(&binlex, &config_home)
        .args([
            "--input",
            input_path.to_string_lossy().as_ref(),
            "--output",
            output_path.to_string_lossy().as_ref(),
            "--architecture",
            "amd64",
            "--minimal",
        ])
        .status()
        .expect("binlex should run");

    assert!(status.success(), "binlex should exit successfully");

    let output = fs::read_to_string(&output_path).expect("output should be readable");
    let block = output
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("line should be json"))
        .find(|value| value.get("type").and_then(|value| value.as_str()) == Some("block"))
        .expect("block output should exist");

    assert_eq!(
        block.get("instructions"),
        Some(&serde_json::json!([0])),
        "block instructions should be emitted as instruction addresses"
    );

    let function = output
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("line should be json"))
        .find(|value| value.get("type").and_then(|value| value.as_str()) == Some("function"))
        .expect("function output should exist");

    assert_eq!(
        function.get("blocks"),
        Some(&serde_json::json!([0])),
        "function blocks should be emitted as block addresses"
    );

    let _ = fs::remove_file(input_path);
    let _ = fs::remove_file(output_path);
    let _ = fs::remove_dir_all(config_home);
}

#[test]
fn test_function_embeddings_are_emitted_from_config() {
    let binlex = binlex_binary();
    let input_path = temp_path("input-embeddings.bin");
    let output_path = temp_path("output-embeddings.jsonl");
    let config_path = temp_path("binlex-embeddings.toml");
    let config_home = temp_path("config-home-embeddings");

    fs::write(&input_path, [0xC3]).expect("input file should be written");
    let mut config = Config::new();
    config.embeddings.llvm.device = "cpu".to_string();
    config.functions.embeddings.llvm.enabled = true;
    fs::write(
        &config_path,
        toml::to_string(&config).expect("config should serialize"),
    )
    .expect("config file should be written");

    let status = command_with_temp_config(&binlex, &config_home)
        .args([
            "--input",
            input_path.to_string_lossy().as_ref(),
            "--output",
            output_path.to_string_lossy().as_ref(),
            "--config",
            config_path.to_string_lossy().as_ref(),
            "--architecture",
            "amd64",
            "--minimal",
        ])
        .status()
        .expect("binlex should run");

    assert!(status.success(), "binlex should exit successfully");

    let output = fs::read_to_string(&output_path).expect("output should be readable");
    let function = output
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("line should be json"))
        .find(|value| value.get("type").and_then(|value| value.as_str()) == Some("function"))
        .expect("function output should exist");

    let vector = function
        .get("embeddings")
        .and_then(|value| value.get("llvm"))
        .and_then(|value| value.get("vector"))
        .and_then(|value| value.as_array())
        .expect("function embeddings.llvm.vector should exist");

    assert!(
        !vector.is_empty(),
        "function embeddings vector should not be empty"
    );

    let _ = fs::remove_file(input_path);
    let _ = fs::remove_file(output_path);
    let _ = fs::remove_file(config_path);
    let _ = fs::remove_dir_all(config_home);
}
