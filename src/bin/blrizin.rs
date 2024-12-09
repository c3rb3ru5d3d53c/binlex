use clap::Parser;
use serde_json::Value;
use std::fs::File;
use std::io::Error;
use std::io::Write;
use std::process;
use binlex::types::LZ4String;
use binlex::AUTHOR;
use binlex::VERSION;
use binlex::io::Stdout;
use binlex::io::JSON;
use binlex::controlflow::SymbolIoJson;

#[derive(Parser, Debug)]
#[command(
    name = "blrizin",
    version = VERSION,
    about =  format!("A Binlex Rizin Tool\n\nVersion: {}", VERSION),
    after_help = format!("Author: {}", AUTHOR),
)]
struct Args {
    #[arg(short, long)]
    input: Option<String>,
    #[arg(short, long)]
    output: Option<String>,
}

fn process_value(parsed: &Value) -> Result<LZ4String, Error> {
    let virtual_address = parsed.get("offset").unwrap().as_u64().unwrap();
    let function_name = parsed.get("name").unwrap().as_str().unwrap().to_string();
    let symbol = SymbolIoJson {
        type_: "symbol".to_string(),
        symbol_type: "function".to_string(),
        name: function_name,
        file_offset: None,
        relative_virtual_address: None,
        virtual_address: Some(virtual_address),
        slice: None,
    };
    let result = serde_json::to_string(&symbol)?;
    Ok(LZ4String::new(&result))
}

fn main() {
    let args = Args::parse();
    let json = JSON::from_file_or_stdin_as_array(args.input, |value| {
        let object = match value.as_object() {
            Some(object) => object,
            None => return false,
        };
        let virtual_address = object.get("offset").and_then(|v| v.as_u64());
        let function_name = object.get("name").and_then(|v| v.as_str()).map(String::from);

        if virtual_address.is_none() || function_name.is_none() {
            return false;
        }
        true
    });

    if args.output.is_none() && json.is_ok(){
        for value in json.unwrap().values() {
            if let Ok(string) = process_value(value) {
                Stdout::print(string);
            }
        }
    } else if args.output.is_some() && json.is_ok() {
        let mut file = match File::create(args.output.unwrap()) {
            Ok(file) => file,
            Err(error) => {
                eprintln!("{}", error);
                std::process::exit(1);
            }
        };
        for value in json.unwrap().values() {
            if let Ok(string) = process_value(value) {
                if let Err(error) = writeln!(file, "{}", string) {
                    eprintln!("{}", error);
                    std::process::exit(1);
                }
            }
        }
    }

    process::exit(0);

}
