use std::process;
use binlex::formats::MACHO;
use binlex::io::Stdout;
use clap::Parser;
use std::fs::File;
use std::io::Write;
use binlex::AUTHOR;
use binlex::VERSION;
use binlex::Config;
use binlex::controlflow::SymbolIoJson;
use binlex::io::Stdin;
use binlex::types::LZ4String;

#[derive(Parser, Debug)]
#[command(
    name = "blmachosym",
    version = VERSION,
    about =  format!("A Binlex MachO Symbol Parsing Tool\n\nVersion: {}", VERSION),
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

    let macho = MACHO::new(args.input, config).unwrap_or_else(|error| {
        eprintln!("{}", error);
        process::exit(1);
    });

    let mut symbols = Vec::<LZ4String>::new();
    for slice in 0..macho.number_of_slices() {
        for (_, symbol) in macho.symbols(slice) {
            let symbol = SymbolIoJson{
                type_: "symbol".to_string(),
                symbol_type: "function".to_string(),
                name: symbol.name,
                file_offset: None,
                relative_virtual_address: None,
                virtual_address: Some(symbol.address),
                slice: Some(slice),
            };
            if let Ok(string) = serde_json::to_string(&symbol) {
                symbols.push(LZ4String::new(&string));
            }
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
