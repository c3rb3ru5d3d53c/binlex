#![cfg(not(target_os = "windows"))]

use binlex::Config;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_path(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be valid")
        .as_nanos();
    std::env::temp_dir().join(format!("binlex-{name}-{nanos}-{}", std::process::id()))
}

fn binlex_binary() -> PathBuf {
    static BINLEX_PATH: OnceLock<PathBuf> = OnceLock::new();

    BINLEX_PATH
        .get_or_init(|| {
            let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            let binary_path = manifest_dir.join("target").join("debug").join("binlex");
            if binary_path.exists() {
                return binary_path;
            }

            let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
            let status = Command::new(cargo)
                .current_dir(&manifest_dir)
                .args(["build", "-p", "binlex-cli", "--bin", "binlex"])
                .status()
                .expect("cargo should build the binlex binary");
            assert!(status.success(), "binlex binary should build");
            binary_path
        })
        .clone()
}

fn vex_processor_binary() -> PathBuf {
    static VEX_PATH: OnceLock<PathBuf> = OnceLock::new();

    VEX_PATH
        .get_or_init(|| {
            let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            let binary_path = manifest_dir
                .join("target")
                .join("debug")
                .join("binlex-processor-vex");
            if binary_path.exists() {
                return binary_path;
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
                .expect("cargo should build the vex processor binary");
            assert!(status.success(), "vex processor binary should build");
            binary_path
        })
        .clone()
}

#[test]
fn test_cli_processors_override_config_for_vex_function_ir() {
    let binlex = binlex_binary();
    let _vex = vex_processor_binary();
    let binlex_dir = PathBuf::from(&binlex)
        .parent()
        .expect("binlex binary should have a parent directory")
        .to_path_buf();

    let input_path = temp_path("input.bin");
    let config_path = temp_path("config.toml");
    let output_path = temp_path("output.jsonl");

    fs::write(&input_path, [0xC3]).expect("input file should be written");

    let mut config = Config::default();
    config.blocks.enabled = false;
    config.instructions.enabled = false;
    config.functions.enabled = true;
    config.processors.enabled = false;
    config.processors.path = Some(binlex_dir.to_string_lossy().into_owned());
    config.processors.processes = 1;
    config.processors.compression = true;
    let vex = config
        .processors
        .ensure_processor("vex")
        .expect("vex processor config should exist");
    vex.enabled = false;
    vex.functions.enabled = true;

    fs::write(
        &config_path,
        toml::to_string(&config).expect("config should serialize"),
    )
    .expect("config file should be written");

    let status = Command::new(&binlex)
        .args([
            "--input",
            input_path.to_string_lossy().as_ref(),
            "--output",
            output_path.to_string_lossy().as_ref(),
            "--architecture",
            "amd64",
            "--config",
            config_path.to_string_lossy().as_ref(),
            "--processors",
            "vex",
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

    assert_eq!(
        function.get("contiguous").and_then(|value| value.as_bool()),
        Some(true)
    );
    assert!(
        function
            .get("processors")
            .and_then(|value| value.get("vex"))
            .and_then(|value| value.get("ir"))
            .and_then(|value| value.as_str())
            .is_some_and(|ir| !ir.is_empty())
    );

    let _ = fs::remove_file(input_path);
    let _ = fs::remove_file(config_path);
    let _ = fs::remove_file(output_path);
}

#[test]
fn test_cli_processors_respect_vex_function_target_config() {
    let binlex = binlex_binary();
    let _vex = vex_processor_binary();
    let binlex_dir = PathBuf::from(&binlex)
        .parent()
        .expect("binlex binary should have a parent directory")
        .to_path_buf();

    let input_path = temp_path("input.bin");
    let config_path = temp_path("config.toml");
    let output_path = temp_path("output.jsonl");

    fs::write(&input_path, [0xC3]).expect("input file should be written");

    let mut config = Config::default();
    config.blocks.enabled = false;
    config.instructions.enabled = false;
    config.functions.enabled = true;
    config.processors.enabled = false;
    config.processors.path = Some(binlex_dir.to_string_lossy().into_owned());
    config.processors.processes = 1;
    config.processors.compression = true;
    let vex = config
        .processors
        .ensure_processor("vex")
        .expect("vex processor config should exist");
    vex.enabled = false;
    vex.functions.enabled = false;

    fs::write(
        &config_path,
        toml::to_string(&config).expect("config should serialize"),
    )
    .expect("config file should be written");

    let status = Command::new(&binlex)
        .args([
            "--input",
            input_path.to_string_lossy().as_ref(),
            "--output",
            output_path.to_string_lossy().as_ref(),
            "--architecture",
            "amd64",
            "--config",
            config_path.to_string_lossy().as_ref(),
            "--processors",
            "vex",
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

    assert!(function.get("processors").is_none());

    let _ = fs::remove_file(input_path);
    let _ = fs::remove_file(config_path);
    let _ = fs::remove_file(output_path);
}
