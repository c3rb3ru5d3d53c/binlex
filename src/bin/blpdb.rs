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

use binlex::controlflow::Symbol;
use binlex::controlflow::SymbolIoJson;
use binlex::io::Stdin;
use binlex::io::Stdout;
use binlex::AUTHOR;
use binlex::VERSION;
use clap::Parser;
use pdb::FallibleIterator;
use std::fs::File;
use std::process;

#[derive(Parser, Debug)]
#[command(
    name = "blpdb",
    version = VERSION,
    about =  format!("A Binlex PDB Parsing Tool\n\nVersion: {}", VERSION),
    after_help = format!("Author: {}", AUTHOR),
)]
struct Cli {
    #[arg(short, long, required = true)]
    input: String,
    #[arg(short, long)]
    output: Option<String>,
    #[arg(long, default_value_t = false)]
    demangle_msvc_names: bool,
}

fn main() -> pdb::Result<()> {
    let cli = Cli::parse();

    let file = File::open(cli.input)?;
    let mut pdb = pdb::PDB::open(file)?;

    let symbol_table = pdb.global_symbols()?;
    let address_map = pdb.address_map()?;

    let mut results = Vec::<SymbolIoJson>::new();
    let mut symbols = symbol_table.iter();
    while let Some(symbol) = symbols.next()? {
        match symbol.parse() {
            Ok(pdb::SymbolData::Public(data)) if data.function => {
                let rva = data.offset.to_rva(&address_map).unwrap_or_default();
                let mut name = data.name.to_string().into_owned();
                if cli.demangle_msvc_names {
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

    Stdin::passthrough();

    for result in results {
        if let Ok(json_string) = serde_json::to_string(&result) {
            Stdout::print(json_string);
        }
    }

    process::exit(0);
}
