use std::process;
use std::path::Path;
use std::sync::Arc;

use clap::Parser;
use glob::glob;
use rayon::prelude::*;
use rayon::ThreadPoolBuilder;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use binlex::{AUTHOR, VERSION};
use binlex::hashing::TLSH;
use binlex::io::{JSON, Stdout};

/// Structure to represent the comparison result between two JSON entries.
#[derive(Serialize, Deserialize)]
pub struct ComparisonJson {
    /// The type of this entity, always `"comparison"`.
    #[serde(rename = "type")]
    pub type_: String,
    /// The JSON entry from the LHS.
    pub lhs: Value,
    /// The JSON entry from the RHS.
    pub rhs: Value,
    /// TLSH Similarity Score
    pub tlsh: Option<u32>,
}

#[derive(Parser, Debug)]
#[command(
    name = "blcompare",
    version = VERSION,
    about =  format!("A Binlex Trait Comparison Tool\n\nVersion: {}", VERSION),
    after_help = format!("Author: {}", AUTHOR),
)]
struct Args {
    /// Input file or wildcard pattern for LHS (Left-Hand Side).
    #[arg(long)]
    input_lhs: Option<String>,

    /// Input file or wildcard pattern for RHS (Right-Hand Side).
    #[arg(long)]
    input_rhs: String,

    /// Number of threads to use.
    #[arg(short, long, default_value_t = 1)]
    pub threads: usize,

    /// Enable recursive wildcard expansion.
    #[arg(short = 'r', long = "recursive")]
    pub recursive: bool,
}

fn main() {
    let args = Args::parse();

    initialize_thread_pool(args.threads);

    let rhs_files = expand_paths(&args.input_rhs, args.recursive);
    if rhs_files.is_empty() {
        eprintln!("No RHS files matched the pattern.");
        process::exit(1);
    }

    match args.input_lhs {
        Some(lhs_pattern) => handle_lhs_files(&lhs_pattern, &rhs_files, args.recursive),
        None => handle_stdin_lhs(&rhs_files),
    }

    process::exit(0);
}

fn initialize_thread_pool(num_threads: usize) {
    ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build_global()
        .unwrap_or_else(|error| {
            eprintln!("Error building thread pool: {}", error);
            process::exit(1);
        });
}

fn expand_paths(pattern: &str, recursive: bool) -> Vec<String> {
    let modified_pattern = if recursive {
        let path = Path::new(pattern);
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let file_pattern = path.file_name().unwrap_or_default().to_str().unwrap_or("");
        parent.join("**").join(file_pattern).to_string_lossy().to_string()
    } else {
        pattern.to_string()
    };

    glob(&modified_pattern)
        .expect("Failed to read glob pattern")
        .filter_map(|entry| {
            match entry {
                Ok(path) if path.is_file() => Some(path.to_string_lossy().to_string()),
                Ok(_) => None,
                Err(e) => {
                    eprintln!("Glob pattern error: {:?}", e);
                    None
                }
            }
        })
        .collect()
}

fn handle_lhs_files(lhs_pattern: &str, rhs_files: &[String], recursive: bool) {
    let lhs_files = expand_paths(lhs_pattern, recursive);
    if lhs_files.is_empty() {
        eprintln!("No LHS files matched the pattern.");
        process::exit(1);
    }

    let pairs: Vec<(String, String)> = lhs_files
        .iter()
        .flat_map(|lhs| rhs_files.iter().map(move |rhs| (lhs.clone(), rhs.clone())))
        .collect();

    pairs.par_iter().for_each(|(lhs_path, rhs_path)| {
        let json_lhs = load_json_with_filter(lhs_path);
        let json_rhs = load_json_with_filter(rhs_path);

        if let (Some(json_lhs), Some(json_rhs)) = (json_lhs, json_rhs) {
            compare_json_entries(&json_lhs, &json_rhs);
        }
    });
}

fn handle_stdin_lhs(rhs_files: &[String]) {
    let json_lhs = match JSON::from_stdin_with_filter(filter_json) {
        Ok(json) => Arc::new(json),
        Err(e) => {
            eprintln!("Error reading LHS from stdin: {}", e);
            process::exit(1);
        }
    };

    eprintln!(
        "Starting comparisons: 1 LHS (from stdin) x {} RHS files = {} pairs.",
        rhs_files.len(),
        rhs_files.len()
    );

    rhs_files.par_iter().for_each(|rhs_path| {
        let json_rhs = load_json_with_filter(rhs_path);

        if let Some(json_rhs) = json_rhs {
            compare_json_entries(&json_lhs, &json_rhs);
        }
    });
}

fn load_json_with_filter(path: &str) -> Option<JSON> {
    match JSON::from_file_with_filter(path, filter_json) {
        Ok(json) => Some(json),
        Err(e) => {
            eprintln!("{}", e);
            None
        }
    }
}

fn filter_json(value: &mut Value) -> bool {
    value.get("architecture").and_then(|v| v.as_str()).is_some()
        && value
            .get("signature")
            .and_then(|v| v.get("tlsh"))
            .and_then(|v| v.as_str())
            .is_some()
}

fn compare_json_entries(json_lhs: &JSON, json_rhs: &JSON) {
    let lhs_entries = json_lhs.values();
    let rhs_entries: Vec<Value> = json_rhs.values().into_iter().cloned().collect();

    for lhs in lhs_entries {
        let lhs_type = match extract_field(lhs, "type") {
            Some(t) => t,
            None => continue,
        };
        let lhs_arch = match extract_field(lhs, "architecture") {
            Some(a) => a,
            None => continue,
        };
        let lhs_tlsh = match extract_nested_field(lhs, "signature", "tlsh") {
            Some(t) => t,
            None => continue,
        };

        for rhs in &rhs_entries {
            let rhs_type = match extract_field(rhs, "type") {
                Some(t) => t,
                None => continue,
            };
            let rhs_arch = match extract_field(rhs, "architecture") {
                Some(a) => a,
                None => continue,
            };
            let rhs_tlsh = match extract_nested_field(rhs, "signature", "tlsh") {
                Some(t) => t,
                None => continue,
            };

            if lhs_type != rhs_type || lhs_arch != rhs_arch {
                continue;
            }

            let tlsh_similarity = TLSH::compare(lhs_tlsh.clone(), rhs_tlsh.clone()).ok();

            let comparison = ComparisonJson {
                type_: "comparison".to_string(),
                lhs: lhs.clone(),
                rhs: rhs.clone(),
                tlsh: tlsh_similarity,
            };

            match serde_json::to_string(&comparison) {
                Ok(serialized) => Stdout::print(serialized),
                Err(e) => eprintln!("Serialization error: {}", e),
            }
        }
    }
}

fn extract_field<'a>(value: &'a Value, field: &str) -> Option<String> {
    value.get(field)?.as_str().map(String::from)
}

fn extract_nested_field<'a>(value: &'a Value, field: &str, subfield: &str) -> Option<String> {
    value.get(field)?.get(subfield)?.as_str().map(String::from)
}
