#![cfg(not(target_os = "windows"))]

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
fn test_block_instructions_are_emitted_as_addresses() {
    let binlex = option_env!("CARGO_BIN_EXE_binlex").expect("binlex binary should be built");
    let input_path = temp_path("input.bin");
    let output_path = temp_path("output.jsonl");

    fs::write(&input_path, [0xC3]).expect("input file should be written");

    let status = Command::new(binlex)
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
}
