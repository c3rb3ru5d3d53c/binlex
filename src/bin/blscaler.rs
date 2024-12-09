use clap::Parser;
use rayon::prelude::*;
use serde_json::Value;
use serde_json::Number;
use std::fs::File;
use std::io::Write;
use std::process;
use rayon::ThreadPoolBuilder;
use binlex::types::LZ4String;
use binlex::AUTHOR;
use binlex::VERSION;
use binlex::io::Stdout;
use binlex::io::JSON;

#[derive(Parser, Debug)]
#[command(
    name = "blscaler",
    version = VERSION,
    about = format!("A Binlex ML Scaler Tool\n\nVersion: {}", VERSION),
    after_help = format!("Author: {}", AUTHOR),
)]
struct Args {
    #[arg(short, long)]
    input: Option<String>,
    #[arg(short, long)]
    output: Option<String>,
    #[arg(short, long, default_value_t = 1)]
    threads: usize
}

fn normalize(data: &[f64]) -> Vec<f64> {
    let min = data.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = data.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    data.iter().map(|&x| (x - min) / (max - min)).collect()
}

fn process_value(mut parsed: Value) -> String {
    if let Some(feature) = parsed
        .get_mut("signature")
        .and_then(|signature| signature.get_mut("feature"))
    {
        if let Some(array) = feature.as_array() {
            let values: Vec<f64> = array.iter().filter_map(|v| v.as_f64()).collect();
            let normalized_values = normalize(&values);
            *feature = Value::Array(
                normalized_values
                    .into_iter()
                    .filter_map(|num| Number::from_f64(num).map(Value::Number)) // Filter out non-finite numbers
                    .collect(),
            );
        }
    }
    let result = match serde_json::to_string(&parsed) {
        Ok(result) => result,
        Err(error) => {
            eprintln!("{}", error);
            process::exit(1);
        }
    };
    return result;
}

fn main() {

    let args = Args::parse();

    ThreadPoolBuilder::new()
        .num_threads(args.threads)
        .build_global()
        .expect("failed to build thread pool");

    let j = match JSON::from_file_or_stdin(args.input) {
        Ok(j) => j,
        Err(error) => {
            eprintln!("{}", error);
            process::exit(1);
        }
    };

    let results: Vec<LZ4String> = j.values().into_par_iter()
        .map(|value| {
            LZ4String::from(process_value(value.clone()))
        })
        .collect();

    if let Some(output_file) = args.output {
        let mut file = match File::create(output_file) {
            Ok(file) => file,
            Err(error) => {
                eprintln!("{}", error);
                std::process::exit(1);
            }
        };
        for result in results {
            if let Err(error) = writeln!(file, "{}", result) {
                eprintln!("{}", error);
                std::process::exit(1);
            }
        }
    } else {
        results.iter().for_each(|result| {
            Stdout::print(result);
        });
    }

    process::exit(0);

}
