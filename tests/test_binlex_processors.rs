#![cfg(not(target_os = "windows"))]

use binlex::Config;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_path(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be valid")
        .as_nanos();
    std::env::temp_dir().join(format!("binlex-{name}-{nanos}-{}", std::process::id()))
}

#[test]
fn test_cli_processors_override_config_for_vex_function_ir() {
    let binlex = option_env!("CARGO_BIN_EXE_binlex").expect("binlex binary should be built");
    let binlex_dir = PathBuf::from(binlex)
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
    config.processors.vex.enabled = false;
    config.processors.vex.functions.enabled = true;

    fs::write(
        &config_path,
        toml::to_string(&config).expect("config should serialize"),
    )
    .expect("config file should be written");

    let status = Command::new(binlex)
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
    let binlex = option_env!("CARGO_BIN_EXE_binlex").expect("binlex binary should be built");
    let binlex_dir = PathBuf::from(binlex)
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
    config.processors.vex.enabled = false;
    config.processors.vex.functions.enabled = false;

    fs::write(
        &config_path,
        toml::to_string(&config).expect("config should serialize"),
    )
    .expect("config file should be written");

    let status = Command::new(binlex)
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
