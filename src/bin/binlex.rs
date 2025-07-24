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

use binlex::controlflow::Attributes;
use binlex::controlflow::Block;
use binlex::controlflow::Function;
use binlex::controlflow::Graph;
use binlex::controlflow::Instruction;
use binlex::controlflow::Symbol;
use binlex::controlflow::Tag;
//use binlex::disassemblers::capstone::x86::Disassembler;
use binlex::disassemblers::capstone::Disassembler;
use binlex::disassemblers::custom::cil::Disassembler as CILDisassembler;
use binlex::formats::pe::PE;
use binlex::formats::File as BLFile;
use binlex::formats::ELF;
use binlex::formats::MACHO;
use binlex::io::Stderr;
use binlex::io::Stdin;
use binlex::io::Stdout;
use binlex::io::JSON;
use binlex::types::LZ4String;
use binlex::Architecture;
use binlex::Config;
use binlex::Format;
use binlex::AUTHOR;
use binlex::VERSION;
use clap::Parser;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use rayon::ThreadPoolBuilder;
use serde_json::json;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashSet;
use std::fs::File;
use std::io::Write;
use std::process;

#[derive(Parser, Debug)]
#[command(
    name = "binlex",
    version = VERSION,
    about = format!("A Binary Pattern Lexer\n\nVersion: {}", VERSION),
    after_help = format!("Author: {}", AUTHOR),
)]
pub struct Args {
    #[arg(short, long)]
    pub input: String,
    #[arg(short, long)]
    pub output: Option<String>,
    #[arg(short, long, help = format!("[{}]", Architecture::to_list()))]
    pub architecture: Option<Architecture>,
    #[arg(short, long)]
    pub config: Option<String>,
    #[arg(short, long)]
    pub threads: Option<usize>,
    #[arg(long, value_delimiter = ',', default_value = None)]
    pub tags: Option<Vec<String>>,
    #[arg(long, default_value_t = false)]
    pub minimal: bool,
    #[arg(short, long, default_value_t = false)]
    pub debug: bool,
    #[arg(long, default_value_t = false)]
    pub enable_instructions: bool,
    #[arg(long, default_value_t = false)]
    pub enable_block_instructions: bool,
    #[arg(long, default_value_t = false)]
    pub disable_hashing: bool,
    #[arg(long, default_value_t = false)]
    pub disable_disassembler_sweep: bool,
    #[arg(long, default_value_t = false)]
    pub disable_function_blocks: bool,
    #[arg(long, default_value_t = false)]
    pub disable_heuristics: bool,
    #[arg(long, default_value_t = false)]
    pub enable_mmap_cache: bool,
    #[arg(long)]
    pub mmap_directory: Option<String>,
}

fn validate_args(args: &Args) {
    if let Some(tags) = &args.tags {
        let mut unique_tags = HashSet::new();
        for tag in tags {
            if !unique_tags.insert(tag) {
                eprintln!("tags must be unique");
                process::exit(1);
            }
        }
    }
}

fn get_elf_function_symbols(elf: &ELF) -> BTreeMap<u64, Symbol> {
    let mut symbols = BTreeMap::<u64, Symbol>::new();

    if Stdin::is_terminal() {
        return symbols;
    }

    let json = JSON::from_stdin_with_filter(|value| {
        let obj = match value.as_object_mut() {
            Some(obj) => obj,
            None => return false,
        };

        let obj_type = obj.get("type").and_then(|v| v.as_str()).map(String::from);
        let symbol_type = obj
            .get("symbol_type")
            .and_then(|v| v.as_str())
            .map(String::from);
        let file_offset = obj.get("file_offset").and_then(|v| v.as_u64());
        let relative_virtual_address = obj.get("relative_virtual_address").and_then(|v| v.as_u64());
        let mut virtual_address = obj.get("virtual_address").and_then(|v| v.as_u64());

        if obj_type.as_deref() != Some("symbol") {
            return false;
        }

        if symbol_type.is_none() {
            return false;
        }

        if file_offset.is_none() && relative_virtual_address.is_none() && virtual_address.is_none()
        {
            return false;
        }

        if virtual_address.is_some() {
            return true;
        }

        if virtual_address.is_none() {
            if let Some(rva) = relative_virtual_address {
                virtual_address = Some(elf.relative_virtual_address_to_virtual_address(rva));
            }
            if let Some(offset) = file_offset {
                if let Some(va) = elf.file_offset_to_virtual_address(offset) {
                    virtual_address = Some(va);
                }
            }

            if let Some(va) = virtual_address {
                obj.insert("virtual_address".to_string(), json!(va));
                return true;
            }
        }

        false
    });

    if json.is_ok() {
        for value in json.unwrap().values() {
            let address = value.get("virtual_address").and_then(|v| v.as_u64());
            let name = value.get("name").and_then(|v| v.as_str());
            let symbol_type = value.get("symbol_type").and_then(|v| v.as_str());
            if address.is_none() {
                continue;
            }
            if name.is_none() {
                continue;
            }
            if symbol_type.is_none() {
                continue;
            }
            let symbol = Symbol::new(
                address.unwrap(),
                symbol_type.unwrap().to_string(),
                name.unwrap().to_string(),
            );
            symbols.insert(address.unwrap(), symbol);
        }
    }

    symbols
}

fn get_macho_function_symbols(macho: &MACHO) -> BTreeMap<u64, Symbol> {
    let mut symbols = BTreeMap::<u64, Symbol>::new();

    if Stdin::is_terminal() {
        return symbols;
    }

    let json = JSON::from_stdin_with_filter(|value| {
        let obj = match value.as_object_mut() {
            Some(obj) => obj,
            None => return false,
        };

        let obj_type = obj.get("type").and_then(|v| v.as_str()).map(String::from);
        let symbol_type = obj
            .get("symbol_type")
            .and_then(|v| v.as_str())
            .map(String::from);
        let file_offset = obj.get("file_offset").and_then(|v| v.as_u64());
        let relative_virtual_address = obj.get("relative_virtual_address").and_then(|v| v.as_u64());
        let mut virtual_address = obj.get("virtual_address").and_then(|v| v.as_u64());
        let slice = obj.get("slice").and_then(|v| v.as_u64());

        if slice.is_none() {
            return false;
        }

        let slice = slice.unwrap() as usize;

        if obj_type.as_deref() != Some("symbol") {
            return false;
        }

        if symbol_type.is_none() {
            return false;
        }

        if file_offset.is_none() && relative_virtual_address.is_none() && virtual_address.is_none()
        {
            return false;
        }

        if virtual_address.is_some() {
            return true;
        }

        if virtual_address.is_none() {
            if let Some(rva) = relative_virtual_address {
                let va = macho.relative_virtual_address_to_virtual_address(rva, slice);
                if va.is_none() {
                    return false;
                }
                virtual_address = Some(va.unwrap());
            }
            if let Some(offset) = file_offset {
                if let Some(va) = macho.file_offset_to_virtual_address(offset, slice) {
                    virtual_address = Some(va);
                }
            }

            if let Some(va) = virtual_address {
                obj.insert("virtual_address".to_string(), json!(va));
                return true;
            }
        }

        false
    });

    if json.is_ok() {
        for value in json.unwrap().values() {
            let address = value.get("virtual_address").and_then(|v| v.as_u64());
            let name = value.get("name").and_then(|v| v.as_str());
            let symbol_type = value.get("symbol_type").and_then(|v| v.as_str());
            if address.is_none() {
                continue;
            }
            if name.is_none() {
                continue;
            }
            if symbol_type.is_none() {
                continue;
            }
            let symbol = Symbol::new(
                address.unwrap(),
                symbol_type.unwrap().to_string(),
                name.unwrap().to_string(),
            );
            symbols.insert(address.unwrap(), symbol);
        }
    }

    symbols
}

fn get_pe_function_symbols(pe: &PE) -> BTreeMap<u64, Symbol> {
    let mut symbols = BTreeMap::<u64, Symbol>::new();

    if Stdin::is_terminal() {
        return symbols;
    }

    let json = JSON::from_stdin_with_filter(|value| {
        let obj = match value.as_object_mut() {
            Some(obj) => obj,
            None => return false,
        };

        let obj_type = obj.get("type").and_then(|v| v.as_str()).map(String::from);
        let symbol_type = obj
            .get("symbol_type")
            .and_then(|v| v.as_str())
            .map(String::from);
        let file_offset = obj.get("file_offset").and_then(|v| v.as_u64());
        let relative_virtual_address = obj.get("relative_virtual_address").and_then(|v| v.as_u64());
        let mut virtual_address = obj.get("virtual_address").and_then(|v| v.as_u64());

        if obj_type.as_deref() != Some("symbol") {
            return false;
        }

        if symbol_type.is_none() {
            return false;
        }

        if file_offset.is_none() && relative_virtual_address.is_none() && virtual_address.is_none()
        {
            return false;
        }

        if virtual_address.is_some() {
            return true;
        }

        if virtual_address.is_none() {
            if let Some(rva) = relative_virtual_address {
                virtual_address = Some(pe.relative_virtual_address_to_virtual_address(rva));
            }
            if let Some(offset) = file_offset {
                if let Some(va) = pe.file_offset_to_virtual_address(offset) {
                    virtual_address = Some(va);
                }
            }

            if let Some(va) = virtual_address {
                obj.insert("virtual_address".to_string(), json!(va));
                return true;
            }
        }

        false
    });

    if json.is_ok() {
        for value in json.unwrap().values() {
            let address = value.get("virtual_address").and_then(|v| v.as_u64());
            let name = value.get("name").and_then(|v| v.as_str());
            let symbol_type = value.get("symbol_type").and_then(|v| v.as_str());
            if address.is_none() {
                continue;
            }
            if name.is_none() {
                continue;
            }
            if symbol_type.is_none() {
                continue;
            }
            let symbol = Symbol::new(
                address.unwrap(),
                symbol_type.unwrap().to_string(),
                name.unwrap().to_string(),
            );
            symbols.insert(address.unwrap(), symbol);
        }
    }

    symbols
}

fn process_output(
    output: Option<String>,
    cfg: &Graph,
    attributes: &Attributes,
    function_symbols: &BTreeMap<u64, Symbol>,
) {
    let mut instructions = Vec::<LZ4String>::new();

    if cfg.config.instructions.enabled {
        instructions = cfg
            .instructions
            .valid()
            .iter()
            .map(|entry| *entry)
            .collect::<Vec<u64>>()
            .par_iter()
            .filter_map(|address| Instruction::new(*address, cfg).ok())
            .filter_map(|instruction| {
                let mut instruction_attributes = Attributes::new();
                let symbol = function_symbols.get(&instruction.address);
                if let Some(symbol) = symbol {
                    instruction_attributes.push(symbol.attribute());
                }
                for attribute in &attributes.values {
                    instruction_attributes.push(attribute.clone());
                }
                instruction
                    .json_with_attributes(instruction_attributes.clone())
                    .ok()
            })
            .map(|js| LZ4String::new(&js))
            .collect();
    }

    let mut blocks = Vec::<LZ4String>::new();

    if cfg.config.blocks.enabled {
        blocks = cfg
            .blocks
            .valid()
            .iter()
            .map(|entry| *entry)
            .collect::<Vec<u64>>()
            .par_iter()
            .filter_map(|address| Block::new(*address, cfg).ok())
            .filter_map(|block| {
                let mut block_attributes = Attributes::new();
                let symbol = function_symbols.get(&block.address);
                if let Some(symbol) = symbol {
                    block_attributes.push(symbol.attribute());
                }
                for attribute in &attributes.values {
                    block_attributes.push(attribute.clone());
                }
                block.json_with_attributes(block_attributes.clone()).ok()
            })
            .map(|js| LZ4String::new(&js))
            .collect();
    }

    let mut functions = Vec::<LZ4String>::new();

    if cfg.config.functions.enabled {
        functions = cfg
            .functions
            .valid()
            .iter()
            .map(|entry| *entry)
            .collect::<Vec<u64>>()
            .par_iter()
            .filter_map(|address| Function::new(*address, cfg).ok())
            .filter_map(|function| {
                let mut function_attributes = Attributes::new();
                let symbol = function_symbols.get(&function.address);
                if let Some(symbol) = symbol {
                    function_attributes.push(symbol.attribute());
                }
                for attribute in &attributes.values {
                    function_attributes.push(attribute.clone());
                }
                function.json_with_attributes(function_attributes).ok()
            })
            .map(|js| LZ4String::new(&js))
            .collect();
    }

    if output.is_none() {
        instructions.iter().for_each(|result| {
            Stdout::print(result);
        });

        blocks.iter().for_each(|result| {
            Stdout::print(result);
        });

        functions.iter().for_each(|result| {
            Stdout::print(result);
        });
    }

    if let Some(output_file) = output {
        let mut file = match File::create(output_file) {
            Ok(file) => file,
            Err(error) => {
                eprintln!("{}", error);
                std::process::exit(1);
            }
        };

        if cfg.config.instructions.enabled {
            for instruction in instructions {
                if let Err(error) = writeln!(file, "{}", instruction) {
                    eprintln!("{}", error);
                    std::process::exit(1);
                }
            }
        }

        for block in blocks {
            if let Err(error) = writeln!(file, "{}", block) {
                eprintln!("{}", error);
                std::process::exit(1);
            }
        }

        for function in functions {
            if let Err(error) = writeln!(file, "{}", function) {
                eprintln!("{}", error);
                std::process::exit(1);
            }
        }
    }
}

fn process_pe(input: String, config: Config, tags: Option<Vec<String>>, output: Option<String>) {
    let mut attributes = Attributes::new();

    let pe = match PE::new(input, config.clone()) {
        Ok(pe) => pe,
        Err(error) => {
            eprintln!("failed to read pe file: {}", error);
            process::exit(1);
        }
    };

    if pe.architecture() == Architecture::UNKNOWN {
        eprintln!("unsupported pe architecture");
        process::exit(1);
    }

    if !config.general.minimal {
        let file_attribute = pe.file.attribute();
        if tags.is_some() {
            for tag in tags.unwrap() {
                attributes.push(Tag::new(tag).attribute());
            }
        }
        attributes.push(file_attribute);
    }

    let function_symbols = get_pe_function_symbols(&pe);

    // for (_, symbol) in &function_symbols {
    //     attributes.push(Attribute::Symbol(symbol.process().clone()));
    // }

    let mut mapped_file = pe.image().unwrap_or_else(|error| {
        eprintln!("failed to map pe image: {}", error);
        process::exit(1)
    });

    Stderr::print_debug(config.clone(), "mapped pe image");

    let image = mapped_file.mmap().unwrap_or_else(|error| {
        eprintln!("failed to get pe virtual image: {}", error);
        process::exit(1);
    });

    Stderr::print_debug(config.clone(), "obtained mapped image pointer");

    let executable_address_ranges = match pe.is_dotnet() {
        true => pe.dotnet_executable_virtual_address_ranges(),
        _ => pe.executable_virtual_address_ranges(),
    };

    let mut entrypoints = BTreeSet::<u64>::new();

    match pe.is_dotnet() {
        true => entrypoints.extend(pe.dotnet_entrypoint_virtual_addresses()),
        _ => entrypoints.extend(pe.entrypoint_virtual_addresses()),
    }

    entrypoints.extend(function_symbols.keys());

    let mut cfg = Graph::new(pe.architecture(), config.clone());

    if !pe.is_dotnet() {
        Stderr::print_debug(config.clone(), "starting pe disassembler");

        let disassembler = match Disassembler::new(
            pe.architecture(),
            image,
            executable_address_ranges.clone(),
            config.clone(),
        ) {
            Ok(disassembler) => disassembler,
            Err(error) => {
                eprintln!("{}", error);
                process::exit(1);
            }
        };

        disassembler
            .disassemble_controlflow(entrypoints.clone(), &mut cfg)
            .unwrap_or_else(|error| {
                eprintln!("{}", error);
                process::exit(1);
            });
    } else if pe.is_dotnet() {
        Stderr::print_debug(config.clone(), "starting pe dotnet disassembler");

        let disassembler = match CILDisassembler::new(
            pe.architecture(),
            image,
            pe.dotnet_metadata_token_virtual_addresses().clone(),
            executable_address_ranges.clone(),
            config.clone(),
        ) {
            Ok(disassembler) => disassembler,
            Err(error) => {
                eprintln!("{}", error);
                process::exit(1);
            }
        };

        disassembler
            .disassemble_controlflow(entrypoints.clone(), &mut cfg)
            .unwrap_or_else(|error| {
                eprintln!("{}", error);
                process::exit(1);
            });
    } else {
        eprintln!("invalid or unsupported pe file");
        process::exit(1);
    }

    process_output(output, &cfg, &attributes, &function_symbols);
}

fn process_elf(input: String, config: Config, tags: Option<Vec<String>>, output: Option<String>) {
    let mut attributes = Attributes::new();

    let elf = ELF::new(input, config.clone()).unwrap_or_else(|error| {
        eprintln!("{}", error);
        process::exit(1);
    });

    if elf.architecture() == Architecture::UNKNOWN {
        eprintln!("unsupported elf architecture");
        process::exit(1);
    }

    if !config.general.minimal {
        let file_attribute = elf.file.attribute();
        if tags.is_some() {
            for tag in tags.unwrap() {
                attributes.push(Tag::new(tag).attribute());
            }
        }
        attributes.push(file_attribute);
    }

    let function_symbols = get_elf_function_symbols(&elf);

    // for (_, symbol) in &function_symbols {
    //     attributes.push(Attribute::Symbol(symbol.process().clone()));
    // }

    let mut mapped_file = elf.image().unwrap_or_else(|error| {
        eprintln!("{}", error);
        process::exit(1)
    });

    let image = mapped_file.mmap().unwrap_or_else(|error| {
        eprintln!("{}", error);
        process::exit(1);
    });

    let executable_address_ranges = elf.executable_virtual_address_ranges();

    let mut entrypoints = BTreeSet::<u64>::new();

    entrypoints.extend(elf.entrypoint_virtual_addresses());

    let mut cfg = Graph::new(elf.architecture(), config.clone());

    let disassembler = match Disassembler::new(
        elf.architecture(),
        image,
        executable_address_ranges.clone(),
        config.clone(),
    ) {
        Ok(disassembler) => disassembler,
        Err(error) => {
            eprintln!("{}", error);
            process::exit(1);
        }
    };

    disassembler
        .disassemble_controlflow(entrypoints, &mut cfg)
        .unwrap_or_else(|error| {
            eprintln!("{}", error);
            process::exit(1);
        });

    process_output(output, &cfg, &attributes, &function_symbols);
}

fn process_code(input: String, config: Config, architecture: Architecture, output: Option<String>) {
    let mut attributes = Attributes::new();

    let mut file = BLFile::new(input, config.clone()).unwrap_or_else(|error| {
        eprintln!("{}", error);
        process::exit(1);
    });
    file.read().unwrap_or_else(|error| {
        eprintln!("{}", error);
        process::exit(1);
    });

    let mut cfg = Graph::new(architecture, config.clone());

    let mut executable_address_ranges = BTreeMap::<u64, u64>::new();
    executable_address_ranges.insert(0, file.size());

    let mut entrypoints = BTreeSet::<u64>::new();

    entrypoints.insert(0x00);

    match architecture {
        Architecture::AMD64 | Architecture::I386 => {
            let disassembler = match Disassembler::new(
                architecture,
                &file.data,
                executable_address_ranges.clone(),
                config.clone(),
            ) {
                Ok(disassembler) => disassembler,
                Err(error) => {
                    eprintln!("{}", error);
                    process::exit(1);
                }
            };

            disassembler
                .disassemble_controlflow(entrypoints, &mut cfg)
                .unwrap_or_else(|error| {
                    eprintln!("{}", error);
                    process::exit(1);
                });
        }
        Architecture::CIL => {
            let disassembler = match CILDisassembler::new(
                architecture,
                &file.data,
                BTreeMap::<u64, u64>::new(),
                executable_address_ranges.clone(),
                config.clone(),
            ) {
                Ok(disassembler) => disassembler,
                Err(error) => {
                    eprintln!("{}", error);
                    process::exit(1);
                }
            };

            disassembler
                .disassemble_controlflow(entrypoints, &mut cfg)
                .unwrap_or_else(|error| {
                    eprintln!("{}", error);
                    process::exit(1);
                });
        }
        _ => {}
    }

    attributes.push(file.attribute());

    let function_symbols = BTreeMap::<u64, Symbol>::new();

    process_output(output, &cfg, &attributes, &function_symbols);
}

fn process_macho(input: String, config: Config, tags: Option<Vec<String>>, output: Option<String>) {
    let mut attributes = Attributes::new();

    let macho = MACHO::new(input, config.clone()).unwrap_or_else(|error| {
        eprintln!("{}", error);
        process::exit(1);
    });

    for slice in 0..macho.number_of_slices() {
        let architecture = macho.architecture(slice);
        if architecture.is_none() {
            continue;
        }
        let architecture = architecture.unwrap();
        if architecture == Architecture::UNKNOWN {
            continue;
        }

        let tags = tags.clone();

        if !config.general.minimal {
            let file_attribute = macho.file.attribute();
            if tags.is_some() {
                for tag in tags.unwrap() {
                    attributes.push(Tag::new(tag).attribute());
                }
            }
            attributes.push(file_attribute);
        }

        let function_symbols = get_macho_function_symbols(&macho);

        // for (_, symbol) in &function_symbols {
        //     attributes.push(Attribute::Symbol(symbol.process().clone()));
        // }

        let mut mapped_file = macho.image(slice).unwrap_or_else(|error| {
            eprintln!("{}", error);
            process::exit(1)
        });

        let image = mapped_file.mmap().unwrap_or_else(|error| {
            eprintln!("{}", error);
            process::exit(1);
        });

        let executable_address_ranges = macho.executable_virtual_address_ranges(slice);

        let mut entrypoints = BTreeSet::<u64>::new();

        entrypoints.extend(macho.entrypoint_virtual_addresses(slice));

        let mut cfg = Graph::new(architecture, config.clone());

        let disassembler = match Disassembler::new(
            architecture,
            image,
            executable_address_ranges.clone(),
            config.clone(),
        ) {
            Ok(disassembler) => disassembler,
            Err(error) => {
                eprintln!("{}", error);
                process::exit(1);
            }
        };

        disassembler
            .disassemble_controlflow(entrypoints, &mut cfg)
            .unwrap_or_else(|error| {
                eprintln!("{}", error);
                process::exit(1);
            });

        process_output(output.clone(), &cfg, &attributes, &function_symbols);
    }
}

fn main() {
    let args = Args::parse();

    validate_args(&args);

    let mut config = Config::new();

    let _ = config.write_default();

    if args.config.is_some() {
        match Config::from_file(&args.config.unwrap().to_string()) {
            Ok(result) => {
                config = result;
            }
            Err(error) => {
                eprintln!("{}", error);
                process::exit(1);
            }
        }
    } else if let Err(error) = config.from_default() {
        eprintln!("failed to read default config: {}", error);
        process::exit(1);
    }

    if args.debug {
        config.general.debug = args.debug;
    }

    if args.threads.is_some() {
        config.general.threads = args.threads.unwrap();
    }

    if args.disable_heuristics {
        config.disable_heuristics();
    }

    if args.disable_hashing {
        config.disable_hashing();
    }

    if args.mmap_directory.is_some() {
        config.mmap.directory = args.mmap_directory.unwrap();
    }

    if args.enable_mmap_cache {
        config.mmap.cache.enabled = args.enable_mmap_cache;
    }

    if args.disable_disassembler_sweep {
        config.disassembler.sweep.enabled = false;
    }

    if args.minimal || config.general.minimal {
        config.enable_minimal();
    }

    if args.enable_instructions {
        config.instructions.enabled = args.enable_instructions;
    }

    if args.enable_block_instructions {
        config.blocks.instructions.enabled = args.enable_block_instructions;
    }

    if args.disable_function_blocks {
        config.functions.blocks.enabled = !args.disable_function_blocks;
    }

    Stderr::print_debug(
        config.clone(),
        "finished reading arguments and configuration",
    );

    ThreadPoolBuilder::new()
        .num_threads(config.general.threads)
        .build_global()
        .unwrap_or_else(|error| {
            eprintln!("{}", error);
            process::exit(1);
        });

    if args.architecture.is_none() {
        let format = Format::from_file(args.input.clone()).unwrap_or_else(|error| {
            eprintln!("{}", error);
            process::exit(1);
        });
        match format {
            Format::PE => {
                Stderr::print_debug(config.clone(), "processing pe");
                process_pe(args.input, config, args.tags, args.output);
            }
            Format::ELF => {
                Stderr::print_debug(config.clone(), "processing elf");
                process_elf(args.input, config, args.tags, args.output);
            }
            Format::MACHO => {
                Stderr::print_debug(config.clone(), "processing macho");
                process_macho(args.input, config, args.tags, args.output);
            }
            _ => {
                eprintln!("unable to identify file format");
                process::exit(1);
            }
        }
    } else {
        let architecture = args.architecture.unwrap();
        match architecture {
            Architecture::AMD64 | Architecture::I386 | Architecture::CIL => {
                Stderr::print_debug(config.clone(), "processing code");
                process_code(args.input, config, architecture, args.output);
            }
            _ => {
                eprintln!("unsupported architecture");
                process::exit(1);
            }
        }
    }

    process::exit(0);
}
