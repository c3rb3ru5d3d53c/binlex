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

use std::process;
use std::fs::File;
use std::io::Write;
use binlex::io::Stdout;
use clap::Parser;
use binlex::AUTHOR;
use binlex::VERSION;
use binlex::formats::ELF;
use binlex::Config;
use binlex::controlflow::SymbolIoJson;
use binlex::io::Stdin;
use binlex::types::LZ4String;

#[derive(Parser, Debug)]
#[command(
    name = "blelfsym",
    version = VERSION,
    about =  format!("A Binlex ELF Symbol Parsing Tool\n\nVersion: {}", VERSION),
    after_help = format!("Author: {}", AUTHOR),
)]
struct Args {
    #[arg(short, long, required = true)]
    input: String,
    #[arg(short, long)]
    output: Option<String>,
}

fn main() -> pdb::Result<()> {
    let args = Args::parse();

    let config = Config::new();

    let elf = ELF::new(args.input, config).unwrap_or_else(|error| {
        eprintln!("{}", error);
        process::exit(1);
    });

    let mut symbols = Vec::<LZ4String>::new();
    for (_, symbol) in elf.symbols() {
        let symbol = SymbolIoJson{
            type_: "symbol".to_string(),
            symbol_type: "function".to_string(),
            name: symbol.name,
            file_offset: None,
            relative_virtual_address: None,
            virtual_address: Some(symbol.address),
            slice: None,
        };
        if let Ok(string) = serde_json::to_string(&symbol) {
            symbols.push(LZ4String::new(&string));
        }
    }

    Stdin::passthrough();

    if args.output.is_none() {
        for symbol in symbols {
            Stdout::print(symbol);
        }
    } else {
        let mut file = match File::create(args.output.unwrap()) {
            Ok(file) => file,
            Err(error) => {
                eprintln!("{}", error);
                std::process::exit(1);
            }
        };
        for symbol in symbols {
            if let Err(error) = writeln!(file, "{}", symbol) {
                eprintln!("{}", error);
                std::process::exit(1);
            }
        }
    }

    process::exit(0);
}
