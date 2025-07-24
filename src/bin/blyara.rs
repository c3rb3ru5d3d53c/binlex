// MIT License
//
// Copyright (c) [2025] [c3rb3ru5d3d53c]
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use clap::Parser;
use serde_json::{Map, Value};
use std::fs::File;
use std::io::{self, BufRead, Write};
use std::process;
use binlex::AUTHOR;
use binlex::VERSION;
use binlex::io::Stdout;

#[derive(Parser, Debug)]
#[command(
    name = "blyara",
    version = VERSION,
    about = format!("A Binlex YARA Generation Tool\n\nVersion: {}", VERSION),
    after_help = format!("Author: {}", AUTHOR),
)]
struct Cli {
    #[arg(short, long)]
    input: Option<String>,
    #[arg(
        short,
        long,
        num_args(2),
        value_names = ["KEY", "VALUE"],
        action = clap::ArgAction::Append
    )]
    metadata: Vec<String>,
    #[arg(short, long, required = true)]
    name: String,
    #[arg(short, long, default_value_t = 1)]
    count: usize,
    #[arg(short, long)]
    output: Option<String>,
}

fn main() {
    let cli = Cli::parse();

    let metadata_map = collect_metadata(&cli.metadata);
    let pattern_map = collect_patterns(&cli.input);

    if pattern_map.is_empty() {
        eprintln!("no signature patterns collected.");
        process::exit(1);
    }

    let signature = generate_signature(&cli.name, &metadata_map, &pattern_map, cli.count);

    if let Some(output_file) = &cli.output {
        if let Err(e) = write_to_file(output_file, &signature) {
            eprintln!("failed to write yara rule to output file: {}", e);
            process::exit(1);
        }
    } else {
        Stdout::print(signature);
    }
}

fn collect_metadata(metadata_vec: &[String]) -> Map<String, Value> {
    let mut metadata_map = Map::new();
    for chunk in metadata_vec.chunks(2) {
        if let [key, value] = chunk {
            metadata_map.insert(key.clone(), Value::String(value.clone()));
        }
    }
    metadata_map
}

fn collect_patterns(input_file: &Option<String>) -> Map<String, Value> {
    let reader: Box<dyn BufRead> = match input_file {
        Some(file_name) => {
            let file = File::open(file_name).unwrap_or_else(|_| {
                eprintln!("failed to open input file: {}", file_name);
                process::exit(1);
            });
            Box::new(io::BufReader::new(file))
        }
        None => Box::new(io::BufReader::new(io::stdin())),
    };

    let mut pattern_map = Map::new();
    for (count, line) in reader.lines().enumerate() {
        match line {
            Ok(l) => {
                pattern_map.insert(
                    format!("trait_{}", count),
                    Value::String(format!("{{{}}}", l)),
                );
            }
            Err(e) => {
                eprintln!("failed to read line: {}", e);
                process::exit(1);
            }
        }
    }
    pattern_map
}

fn generate_signature(
    name: &str,
    metadata_map: &Map<String, Value>,
    pattern_map: &Map<String, Value>,
    count: usize,
) -> String {
    let mut signature = format!("rule {} {{\n", name);

    if !metadata_map.is_empty() {
        signature.push_str("    meta:\n");
        for (key, value) in metadata_map {
            signature.push_str(&format!("        {} = {}\n", key, value));
        }
    }

    signature.push_str("    strings:\n");
    for (key, value) in pattern_map {
        signature.push_str(&format!(
            "        ${} = {}\n",
            key,
            value.as_str().unwrap_or("")
        ));
    }

    signature.push_str("    condition:\n");
    signature.push_str(&format!("        {} of them\n", count));
    signature.push_str("}\n");

    signature
}

fn write_to_file(output_file: &str, content: &str) -> io::Result<()> {
    let mut file = File::create(output_file)?;
    file.write_all(content.as_bytes())
}
