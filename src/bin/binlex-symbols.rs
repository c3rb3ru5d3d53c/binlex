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

use binlex::AUTHOR;
use binlex::Config;
use binlex::VERSION;
use binlex::formats::ELF;
use binlex::formats::MACHO;
use binlex::formats::Symbol;
use binlex::formats::SymbolIoJson;
use binlex::io::JSON;
use binlex::io::Stdout;
use clap::{Args, Parser, Subcommand};
use pdb::FallibleIterator;
use std::fs::File;
use std::io::Write;
use std::process;

type AppResult<T> = Result<T, String>;

#[derive(Parser, Debug)]
#[command(
    name = "binlex-symbols",
    version = VERSION,
    about = format!("A Binlex Symbol Parsing Tool\n\nVersion: {}", VERSION),
    after_help = format!("Author: {}", AUTHOR),
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Elf(FileArgs),
    Macho(FileArgs),
    Pdb(PdbArgs),
    Rizin(RizinArgs),
}

#[derive(Args, Debug, Clone)]
struct FileArgs {
    #[arg(short, long, required = true)]
    input: String,
    #[arg(short, long)]
    output: Option<String>,
}

#[derive(Args, Debug, Clone)]
struct PdbArgs {
    #[arg(short, long, required = true)]
    input: String,
    #[arg(short, long)]
    output: Option<String>,
    #[arg(long, default_value_t = false)]
    demangle_msvc_names: bool,
}

#[derive(Args, Debug, Clone)]
struct RizinArgs {
    #[arg(short, long)]
    input: Option<String>,
    #[arg(short, long)]
    output: Option<String>,
    #[arg(long, default_value_t = false, help = "Read the Rizin JSON array from standard input")]
    stdin: bool,
}

fn write_symbols_to_stdout(symbols: &[SymbolIoJson]) -> AppResult<()> {
    for line in serialize_symbols(symbols)? {
        Stdout::print(line);
    }
    Ok(())
}

fn write_symbols_to_file(path: &str, symbols: &[SymbolIoJson]) -> AppResult<()> {
    let mut file = File::create(path).map_err(|error| error.to_string())?;
    for line in serialize_symbols(symbols)? {
        writeln!(file, "{}", line).map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn serialize_symbols(symbols: &[SymbolIoJson]) -> AppResult<Vec<String>> {
    symbols
        .iter()
        .map(|symbol| serde_json::to_string(symbol).map_err(|error| error.to_string()))
        .collect()
}

fn emit_symbols(symbols: &[SymbolIoJson], output: Option<&str>) -> AppResult<()> {
    match output {
        Some(path) => write_symbols_to_file(path, symbols),
        None => write_symbols_to_stdout(symbols),
    }
}

fn read_elf_symbols(input: &str) -> AppResult<Vec<SymbolIoJson>> {
    let config = Config::new();
    let elf = ELF::new(input.to_string(), config).map_err(|error| error.to_string())?;

    Ok(elf
        .symbols()
        .into_values()
        .map(|symbol| SymbolIoJson {
            type_: "symbol".to_string(),
            symbol_type: "function".to_string(),
            name: symbol.name,
            file_offset: None,
            relative_virtual_address: None,
            virtual_address: Some(symbol.address),
            slice: None,
        })
        .collect())
}

fn read_macho_symbols(input: &str) -> AppResult<Vec<SymbolIoJson>> {
    let config = Config::new();
    let macho = MACHO::new(input.to_string(), config).map_err(|error| error.to_string())?;
    let mut symbols = Vec::<SymbolIoJson>::new();

    for slice in macho.slices() {
        for symbol in slice.symbols().into_values() {
            symbols.push(SymbolIoJson {
                type_: "symbol".to_string(),
                symbol_type: "function".to_string(),
                name: symbol.name,
                file_offset: None,
                relative_virtual_address: None,
                virtual_address: Some(symbol.address),
                slice: Some(slice.index()),
            });
        }
    }

    Ok(symbols)
}

fn read_pdb_symbols(input: &str, demangle_msvc_names: bool) -> AppResult<Vec<SymbolIoJson>> {
    let file = File::open(input).map_err(|error| error.to_string())?;
    let mut pdb = pdb::PDB::open(file).map_err(|error| error.to_string())?;
    let symbol_table = pdb.global_symbols().map_err(|error| error.to_string())?;
    let address_map = pdb.address_map().map_err(|error| error.to_string())?;
    let mut results = Vec::<SymbolIoJson>::new();
    let mut symbols = symbol_table.iter();

    while let Some(symbol) = symbols.next().map_err(|error| error.to_string())? {
        match symbol.parse() {
            Ok(pdb::SymbolData::Public(data)) if data.function => {
                let rva = data.offset.to_rva(&address_map).unwrap_or_default();
                let mut name = data.name.to_string().into_owned();
                if demangle_msvc_names {
                    name = Symbol::demangle_msvc_name(&name);
                }
                results.push(SymbolIoJson {
                    type_: "symbol".to_string(),
                    symbol_type: "function".to_string(),
                    name,
                    file_offset: None,
                    relative_virtual_address: Some(rva.0 as u64),
                    virtual_address: None,
                    slice: None,
                });
            }
            _ => {}
        }
    }

    Ok(results)
}

fn read_rizin_symbols(input: Option<&str>) -> AppResult<Vec<SymbolIoJson>> {
    let json = JSON::from_file_or_stdin_as_array(input.map(String::from), |value| {
        let object = match value.as_object() {
            Some(object) => object,
            None => return false,
        };
        let virtual_address = object.get("offset").and_then(|v| v.as_u64());
        let function_name = object
            .get("name")
            .and_then(|v| v.as_str())
            .map(String::from);

        virtual_address.is_some() && function_name.is_some()
    })
    .map_err(|error| error.to_string())?;

    let mut symbols = Vec::<SymbolIoJson>::new();
    for value in json.values() {
        let virtual_address = value
            .get("offset")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| "missing rizin offset field".to_string())?;
        let function_name = value
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "missing rizin name field".to_string())?
            .to_string();

        symbols.push(SymbolIoJson {
            type_: "symbol".to_string(),
            symbol_type: "function".to_string(),
            name: function_name,
            file_offset: None,
            relative_virtual_address: None,
            virtual_address: Some(virtual_address),
            slice: None,
        });
    }

    Ok(symbols)
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Elf(args) => read_elf_symbols(&args.input).and_then(|symbols| {
            emit_symbols(&symbols, args.output.as_deref())
        }),
        Command::Macho(args) => read_macho_symbols(&args.input).and_then(|symbols| {
            emit_symbols(&symbols, args.output.as_deref())
        }),
        Command::Pdb(args) => read_pdb_symbols(&args.input, args.demangle_msvc_names).and_then(
            |symbols| emit_symbols(&symbols, args.output.as_deref()),
        ),
        Command::Rizin(args) => {
            if args.stdin && args.input.is_some() {
                Err("use either --input or --stdin for rizin".to_string())
            } else if !args.stdin && args.input.is_none() {
                Err("rizin requires --input or --stdin".to_string())
            } else {
                let input = if args.stdin {
                    None
                } else {
                    args.input.as_deref()
                };
                read_rizin_symbols(input).and_then(|symbols| emit_symbols(&symbols, args.output.as_deref()))
            }
        }
    };

    if let Err(error) = result {
        eprintln!("{}", error);
        process::exit(1);
    }
}
