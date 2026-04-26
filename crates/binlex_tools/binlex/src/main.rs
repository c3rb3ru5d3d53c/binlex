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

use binlex::controlflow::Block;
use binlex::controlflow::Function;
use binlex::controlflow::Graph;
use binlex::controlflow::Instruction;
//use binlex::disassemblers::capstone::x86::Disassembler;
use binlex::AUTHOR;
use binlex::Architecture;
use binlex::Config;
use binlex::Magic;
use binlex::VERSION;
use binlex::compression::LZ4String;
use binlex::disassemblers::capstone::Disassembler;
use binlex::disassemblers::cil::Disassembler as CILDisassembler;
use binlex::formats::ELF;
use binlex::formats::File as BLFile;
use binlex::formats::MACHO;
use binlex::formats::Symbol;
use binlex::formats::SymbolKind;
use binlex::formats::pe::PE;
use binlex::io::JSON;
use binlex::io::Stderr;
use binlex::io::Stdin;
use binlex::io::Stdout;
use binlex::metadata::Attributes;
use binlex::metadata::Tag;
use binlex::processor::{ProcessorTarget, apply_output};
use clap::Parser;
use rayon::ThreadPoolBuilder;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use serde_json::json;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashSet;
use std::fs::File;
use std::io::Write;
use std::process;
use std::time::Instant;

fn colocated_processor_directory(processors: &[String]) -> Option<String> {
    let current_exe = std::env::current_exe().ok()?;
    let parent = current_exe.parent()?;
    let has_all = processors.iter().all(|processor| {
        let filename = binlex::runtime::dispatch::processor_backend_filename(processor);
        parent.join(filename).is_file()
    });
    if has_all {
        Some(parent.to_string_lossy().into_owned())
    } else {
        None
    }
}

#[derive(Parser, Debug, Clone)]
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
    #[arg(
        long,
        default_value_t = false,
        help = "Read symbol JSON from standard input"
    )]
    pub stdin: bool,
    #[arg(short, long, help = format!("[{}]", Architecture::to_list()))]
    pub architecture: Option<Architecture>,
    #[arg(short, long)]
    pub config: Option<String>,
    #[arg(short, long)]
    pub threads: Option<usize>,
    #[arg(long)]
    pub processes: Option<usize>,
    #[arg(long, value_delimiter = ',', default_value = None)]
    pub tags: Option<Vec<String>>,
    #[arg(long, default_value_t = false)]
    pub minimal: bool,
    #[arg(short, long, default_value_t = false)]
    pub debug: bool,
    #[arg(long, default_value_t = false)]
    pub enable_instructions: bool,
    #[arg(long, default_value_t = false)]
    pub enable_mmap_cache: bool,
    #[arg(long)]
    pub mmap_directory: Option<String>,
    #[arg(long, value_delimiter = ',')]
    pub processors: Option<Vec<String>>,
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

    if let Some(processors) = &args.processors {
        let mut unique_processors = HashSet::new();
        for processor in processors {
            if !unique_processors.insert(processor) {
                eprintln!("processors must be unique");
                process::exit(1);
            }
        }
    }

    if args.processes == Some(0) {
        eprintln!("processes must be greater than 0");
        process::exit(1);
    }

    if args.stdin && Stdin::is_terminal() {
        eprintln!("--stdin requires piped standard input");
        process::exit(1);
    }
}

fn apply_cli_overrides(args: &Args, config: &mut Config) {
    if args.debug {
        config.debug = args.debug;
    }

    if let Some(threads) = args.threads {
        config.threads = threads;
    }

    if let Some(processes) = args.processes {
        config.processors.processes = processes;
    }

    if let Some(processors) = &args.processors {
        if let Some(directory) = colocated_processor_directory(processors) {
            config.processors.path = Some(directory);
        }
        let enabled_processors: HashSet<_> = processors.iter().cloned().collect();
        let discovered =
            binlex::processor::registered_processor_registrations_for_config(&config.processors);
        let discovered_names: HashSet<_> =
            discovered.iter().map(|entry| entry.name.clone()).collect();
        for processor_name in &enabled_processors {
            if !discovered_names.contains(processor_name) {
                eprintln!("unknown processor: {}", processor_name);
                process::exit(1);
            }
        }
        config.processors.enabled = !enabled_processors.is_empty();
        for registration in discovered {
            if let Some(processor) = config.processors.ensure_processor(&registration.name) {
                processor.enabled = enabled_processors.contains(&registration.name);
            }
        }
    }

    if let Some(mmap_directory) = &args.mmap_directory {
        config.mmap.directory = mmap_directory.clone();
    }

    if args.enable_mmap_cache {
        config.mmap.cache.enabled = args.enable_mmap_cache;
    }

    if args.minimal || config.minimal {
        config.enable_minimal();
    }

    if args.enable_instructions {
        config.instructions.enabled = args.enable_instructions;
    }
}

fn print_stage_timing(config: &Config, stage: &str, started_at: Instant) {
    if config.debug {
        Stderr::print(format!(
            "[timing] {}: {:.3} ms",
            stage,
            started_at.elapsed().as_secs_f64() * 1000.0
        ));
    }
}

fn get_elf_function_symbols(elf: &ELF, read_stdin: bool) -> BTreeMap<u64, Symbol> {
    let mut symbols = BTreeMap::<u64, Symbol>::new();

    if !read_stdin {
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
                parse_symbol_kind(symbol_type.unwrap()),
                name.unwrap().to_string(),
            );
            symbols.insert(address.unwrap(), symbol);
        }
    }

    symbols
}

fn get_macho_function_symbols(macho: &MACHO, read_stdin: bool) -> BTreeMap<u64, Symbol> {
    let mut symbols = BTreeMap::<u64, Symbol>::new();

    if !read_stdin {
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

        let slice = match macho.slice(slice.unwrap() as usize) {
            Some(slice) => slice,
            None => return false,
        };

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
                let va = slice.relative_virtual_address_to_virtual_address(rva);
                if va.is_none() {
                    return false;
                }
                virtual_address = Some(va.unwrap());
            }
            if let Some(offset) = file_offset {
                if let Some(va) = slice.file_offset_to_virtual_address(offset) {
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
                parse_symbol_kind(symbol_type.unwrap()),
                name.unwrap().to_string(),
            );
            symbols.insert(address.unwrap(), symbol);
        }
    }

    symbols
}

fn get_pe_function_symbols(pe: &PE, read_stdin: bool) -> BTreeMap<u64, Symbol> {
    let mut symbols = BTreeMap::<u64, Symbol>::new();

    if !read_stdin {
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
                parse_symbol_kind(symbol_type.unwrap()),
                name.unwrap().to_string(),
            );
            symbols.insert(address.unwrap(), symbol);
        }
    }

    symbols
}

fn parse_symbol_kind(value: &str) -> SymbolKind {
    match value {
        "function" => SymbolKind::Function,
        "import" => SymbolKind::Import,
        "export" => SymbolKind::Export,
        _ => SymbolKind::Unknown,
    }
}

fn process_output(
    output: Option<String>,
    cfg: &Graph,
    attributes: &Attributes,
    function_symbols: &BTreeMap<u64, Symbol>,
) {
    let mut instructions = Vec::<LZ4String>::new();

    if !binlex::processor::enabled_processors_for_target(
        &cfg.config,
        binlex::processor::ProcessorTarget::Graph,
    )
    .is_empty()
    {
        match cfg.process_graph() {
            Ok(()) => Stderr::print_debug(&cfg.config, "process_graph completed"),
            Err(error) => {
                Stderr::print_debug(&cfg.config, format!("process_graph failed: {}", error))
            }
        }
    }
    if !binlex::processor::enabled_processors_for_target(
        &cfg.config,
        binlex::processor::ProcessorTarget::Complete,
    )
    .is_empty()
    {
        let _ = cfg.process_complete();
    }

    let block_output_count = cfg
        .blocks
        .valid()
        .iter()
        .filter(|entry| {
            cfg.processor_outputs(ProcessorTarget::Block, **entry)
                .is_some()
        })
        .count();
    let function_output_count = cfg
        .functions
        .valid()
        .iter()
        .filter(|entry| {
            cfg.processor_outputs(ProcessorTarget::Function, **entry)
                .is_some()
        })
        .count();
    if cfg.config.instructions.enabled {
        let _ = cfg.process_instructions();
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
                let mut raw = instruction.process_with_attributes(instruction_attributes.clone());
                if let Some(outputs) = cfg.processor_outputs(
                    binlex::processor::ProcessorTarget::Instruction,
                    instruction.address,
                ) {
                    for (processor_name, output) in &outputs {
                        binlex::processor::apply_output(
                            raw.processors.get_or_insert_with(Default::default),
                            processor_name,
                            output,
                        );
                    }
                }
                serde_json::to_string(&raw).ok()
            })
            .map(|js| LZ4String::new(&js))
            .collect();
    }

    let mut blocks = Vec::<LZ4String>::new();

    if cfg.config.blocks.enabled {
        let _ = cfg.process_blocks();
        Stderr::print_debug(
            &cfg.config,
            format!(
                "block processor outputs attached to {} blocks",
                block_output_count
            ),
        );
        blocks = cfg
            .blocks
            .valid()
            .iter()
            .map(|entry| *entry)
            .collect::<Vec<u64>>()
            .par_iter()
            .filter_map(|address| Block::new(*address, cfg).ok())
            .map(|block| {
                let mut block_attributes = Attributes::new();
                let symbol = function_symbols.get(&block.address);
                if let Some(symbol) = symbol {
                    block_attributes.push(symbol.attribute());
                }
                for attribute in &attributes.values {
                    block_attributes.push(attribute.clone());
                }
                let mut raw = block.process_with_attributes(block_attributes);
                if let Some(outputs) = cfg.processor_outputs(ProcessorTarget::Block, block.address)
                {
                    for (processor_name, output) in &outputs {
                        apply_output(
                            raw.processors.get_or_insert_with(Default::default),
                            processor_name,
                            output,
                        );
                    }
                }
                raw
            })
            .filter_map(|raw| serde_json::to_string(&raw).ok())
            .map(|js| LZ4String::new(&js))
            .collect();
    }

    let mut functions = Vec::<LZ4String>::new();

    if cfg.config.functions.enabled {
        let _ = cfg.process_functions();
        Stderr::print_debug(
            &cfg.config,
            format!(
                "function processor outputs attached to {} functions",
                function_output_count
            ),
        );
        let function_outputs = cfg
            .functions
            .valid()
            .iter()
            .map(|entry| *entry)
            .collect::<Vec<u64>>()
            .par_iter()
            .filter_map(|address| Function::new(*address, cfg).ok())
            .map(|function| {
                let mut function_attributes = Attributes::new();
                let symbol = function_symbols.get(&function.address);
                if let Some(symbol) = symbol {
                    function_attributes.push(symbol.attribute());
                }
                for attribute in &attributes.values {
                    function_attributes.push(attribute.clone());
                }
                let mut raw = function.process_with_attributes(function_attributes);
                if let Some(outputs) =
                    cfg.processor_outputs(ProcessorTarget::Function, function.address)
                {
                    for (processor_name, output) in &outputs {
                        apply_output(
                            raw.processors.get_or_insert_with(Default::default),
                            processor_name,
                            output,
                        );
                    }
                }
                raw
            })
            .filter_map(|raw| serde_json::to_string(&raw).ok())
            .collect::<Vec<String>>();

        functions = function_outputs
            .iter()
            .map(|js| LZ4String::new(js))
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

fn process_pe(
    _args: &Args,
    input: String,
    config: Config,
    tags: Option<Vec<String>>,
    output: Option<String>,
    read_stdin: bool,
) {
    let process_started_at = Instant::now();
    let mut attributes = Attributes::new();

    let pe_started_at = Instant::now();
    let pe = match PE::new(input, config.clone()) {
        Ok(pe) => pe,
        Err(error) => {
            eprintln!("failed to read pe file: {}", error);
            process::exit(1);
        }
    };
    print_stage_timing(&config, "pe.new", pe_started_at);

    if pe.architecture() == Architecture::UNKNOWN {
        eprintln!("unsupported pe architecture");
        process::exit(1);
    }

    if !config.minimal {
        let file_attribute = pe.file.attribute();
        if tags.is_some() {
            for tag in tags.unwrap() {
                attributes.push(Tag::new(tag).attribute());
            }
        }
        attributes.push(file_attribute);
    }

    let function_symbols = get_pe_function_symbols(&pe, read_stdin);

    // for (_, symbol) in &function_symbols {
    //     attributes.push(Attribute::Symbol(symbol.process().clone()));
    // }

    let image_started_at = Instant::now();
    let mut mapped_file = pe.image().unwrap_or_else(|error| {
        eprintln!("failed to map pe image: {}", error);
        process::exit(1)
    });

    Stderr::print_debug(&config, "mapped pe image");

    let image = mapped_file.mmap().unwrap_or_else(|error| {
        eprintln!("failed to get pe virtual image: {}", error);
        process::exit(1);
    });
    print_stage_timing(&config, "pe.image", image_started_at);

    Stderr::print_debug(&config, "obtained mapped image pointer");

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

    let runtime_config = config.clone();
    let mut cfg = Graph::new(pe.architecture(), runtime_config.clone());

    if !pe.is_dotnet() {
        Stderr::print_debug(&config, "starting pe disassembler");
        let disassembly_started_at = Instant::now();

        let disassembler = match Disassembler::new(
            pe.architecture(),
            image,
            executable_address_ranges.clone(),
            runtime_config.clone(),
        ) {
            Ok(disassembler) => disassembler,
            Err(error) => {
                eprintln!("{}", error);
                process::exit(1);
            }
        };

        disassembler
            .disassemble(entrypoints.clone(), &mut cfg)
            .unwrap_or_else(|error| {
                eprintln!("{}", error);
                process::exit(1);
            });
        print_stage_timing(&config, "pe.disassemble", disassembly_started_at);
    } else if pe.is_dotnet() {
        Stderr::print_debug(&config, "starting pe dotnet disassembler");
        let disassembly_started_at = Instant::now();

        let disassembler = match CILDisassembler::new(
            pe.architecture(),
            image,
            pe.dotnet_metadata_token_virtual_addresses().clone(),
            executable_address_ranges.clone(),
            runtime_config.clone(),
        ) {
            Ok(disassembler) => disassembler,
            Err(error) => {
                eprintln!("{}", error);
                process::exit(1);
            }
        };

        disassembler
            .disassemble(entrypoints.clone(), &mut cfg)
            .unwrap_or_else(|error| {
                eprintln!("{}", error);
                process::exit(1);
            });
        print_stage_timing(&config, "pe.dotnet.disassemble", disassembly_started_at);
    } else {
        eprintln!("invalid or unsupported pe file");
        process::exit(1);
    }

    let output_started_at = Instant::now();
    process_output(output, &cfg, &attributes, &function_symbols);
    print_stage_timing(&config, "pe.process_output", output_started_at);
    print_stage_timing(&config, "pe.total", process_started_at);
}

fn process_elf(
    _args: &Args,
    input: String,
    config: Config,
    tags: Option<Vec<String>>,
    output: Option<String>,
    read_stdin: bool,
) {
    let process_started_at = Instant::now();
    let mut attributes = Attributes::new();

    let elf_started_at = Instant::now();
    let elf = ELF::new(input, config.clone()).unwrap_or_else(|error| {
        eprintln!("{}", error);
        process::exit(1);
    });
    print_stage_timing(&config, "elf.new", elf_started_at);

    if elf.architecture() == Architecture::UNKNOWN {
        eprintln!("unsupported elf architecture");
        process::exit(1);
    }

    if !config.minimal {
        let file_attribute = elf.file.attribute();
        if tags.is_some() {
            for tag in tags.unwrap() {
                attributes.push(Tag::new(tag).attribute());
            }
        }
        attributes.push(file_attribute);
    }

    let function_symbols = get_elf_function_symbols(&elf, read_stdin);

    // for (_, symbol) in &function_symbols {
    //     attributes.push(Attribute::Symbol(symbol.process().clone()));
    // }

    let image_started_at = Instant::now();
    let mut mapped_file = elf.image().unwrap_or_else(|error| {
        eprintln!("{}", error);
        process::exit(1)
    });

    let image = mapped_file.mmap().unwrap_or_else(|error| {
        eprintln!("{}", error);
        process::exit(1);
    });
    print_stage_timing(&config, "elf.image", image_started_at);

    let executable_address_ranges = elf.executable_virtual_address_ranges();

    let mut entrypoints = BTreeSet::<u64>::new();

    entrypoints.extend(elf.entrypoint_virtual_addresses());

    let runtime_config = config.clone();
    let mut cfg = Graph::new(elf.architecture(), runtime_config.clone());

    let disassembly_started_at = Instant::now();
    let disassembler = match Disassembler::new(
        elf.architecture(),
        image,
        executable_address_ranges.clone(),
        runtime_config.clone(),
    ) {
        Ok(disassembler) => disassembler,
        Err(error) => {
            eprintln!("{}", error);
            process::exit(1);
        }
    };

    disassembler
        .disassemble(entrypoints, &mut cfg)
        .unwrap_or_else(|error| {
            eprintln!("{}", error);
            process::exit(1);
        });
    print_stage_timing(&config, "elf.disassemble", disassembly_started_at);

    let output_started_at = Instant::now();
    process_output(output, &cfg, &attributes, &function_symbols);
    print_stage_timing(&config, "elf.process_output", output_started_at);
    print_stage_timing(&config, "elf.total", process_started_at);
}

fn process_code(
    _args: &Args,
    input: String,
    config: Config,
    architecture: Architecture,
    output: Option<String>,
) {
    let process_started_at = Instant::now();
    let mut attributes = Attributes::new();

    let file_started_at = Instant::now();
    let mut file = BLFile::new(input, config.clone()).unwrap_or_else(|error| {
        eprintln!("{}", error);
        process::exit(1);
    });
    file.read().unwrap_or_else(|error| {
        eprintln!("{}", error);
        process::exit(1);
    });
    print_stage_timing(&config, "code.read", file_started_at);

    let runtime_config = config.clone();
    let mut cfg = Graph::new(architecture, runtime_config.clone());

    let mut executable_address_ranges = BTreeMap::<u64, u64>::new();
    executable_address_ranges.insert(0, file.size());

    let mut entrypoints = BTreeSet::<u64>::new();

    entrypoints.insert(0x00);

    match architecture {
        Architecture::ARM64 | Architecture::AMD64 | Architecture::I386 => {
            let disassembly_started_at = Instant::now();
            let disassembler = match Disassembler::new(
                architecture,
                &file.data,
                executable_address_ranges.clone(),
                runtime_config.clone(),
            ) {
                Ok(disassembler) => disassembler,
                Err(error) => {
                    eprintln!("{}", error);
                    process::exit(1);
                }
            };

            disassembler
                .disassemble(entrypoints, &mut cfg)
                .unwrap_or_else(|error| {
                    eprintln!("{}", error);
                    process::exit(1);
                });
            print_stage_timing(&config, "code.disassemble", disassembly_started_at);
        }
        Architecture::CIL => {
            let disassembly_started_at = Instant::now();
            let disassembler = match CILDisassembler::new(
                architecture,
                &file.data,
                BTreeMap::<u64, u64>::new(),
                executable_address_ranges.clone(),
                runtime_config.clone(),
            ) {
                Ok(disassembler) => disassembler,
                Err(error) => {
                    eprintln!("{}", error);
                    process::exit(1);
                }
            };

            disassembler
                .disassemble(entrypoints, &mut cfg)
                .unwrap_or_else(|error| {
                    eprintln!("{}", error);
                    process::exit(1);
                });
            print_stage_timing(&config, "code.dotnet.disassemble", disassembly_started_at);
        }
        _ => {}
    }

    attributes.push(file.attribute());

    let function_symbols = BTreeMap::<u64, Symbol>::new();

    let output_started_at = Instant::now();
    process_output(output, &cfg, &attributes, &function_symbols);
    print_stage_timing(&config, "code.process_output", output_started_at);
    print_stage_timing(&config, "code.total", process_started_at);
}

fn process_macho(
    _args: &Args,
    input: String,
    config: Config,
    tags: Option<Vec<String>>,
    output: Option<String>,
    read_stdin: bool,
) {
    let process_started_at = Instant::now();
    let mut attributes = Attributes::new();

    let macho_started_at = Instant::now();
    let macho = MACHO::new(input, config.clone()).unwrap_or_else(|error| {
        eprintln!("{}", error);
        process::exit(1);
    });
    print_stage_timing(&config, "macho.new", macho_started_at);

    for (slice_index, slice) in macho.slices().enumerate() {
        let architecture = slice.architecture();
        if architecture == Architecture::UNKNOWN {
            Stderr::print_debug(
                &config,
                format!("macho slice {}: skipping unknown architecture", slice_index),
            );
            continue;
        }

        let tags = tags.clone();

        if !config.minimal {
            let file_attribute = macho.file.attribute();
            if tags.is_some() {
                for tag in tags.unwrap() {
                    attributes.push(Tag::new(tag).attribute());
                }
            }
            attributes.push(file_attribute);
        }

        let function_symbols = get_macho_function_symbols(&macho, read_stdin);
        Stderr::print_debug(
            &config,
            format!(
                "macho slice {}: architecture={}, function_symbols={}",
                slice_index,
                architecture,
                function_symbols.len()
            ),
        );

        // for (_, symbol) in &function_symbols {
        //     attributes.push(Attribute::Symbol(symbol.process().clone()));
        // }

        let image_started_at = Instant::now();
        Stderr::print_debug(
            &config,
            format!("macho slice {}: mapping image", slice_index),
        );
        let mut mapped_file = slice.image().unwrap_or_else(|error| {
            eprintln!("{}", error);
            process::exit(1)
        });

        let image = mapped_file.mmap().unwrap_or_else(|error| {
            eprintln!("{}", error);
            process::exit(1);
        });
        print_stage_timing(&config, "macho.image", image_started_at);

        let executable_address_ranges = slice.executable_virtual_address_ranges();
        Stderr::print_debug(
            &config,
            format!(
                "macho slice {}: executable ranges={} image_size={} bytes",
                slice_index,
                executable_address_ranges.len(),
                image.len()
            ),
        );

        let mut entrypoints = BTreeSet::<u64>::new();
        entrypoints.extend(
            slice
                .entrypoint_virtual_addresses()
                .into_iter()
                .filter(|address| {
                    executable_address_ranges
                        .iter()
                        .any(|(start, end)| *address >= *start && *address < *end)
                }),
        );
        Stderr::print_debug(
            &config,
            format!(
                "macho slice {}: filtered entrypoints={:?}",
                slice_index, entrypoints
            ),
        );

        let runtime_config = config.clone();
        let mut cfg = Graph::new(architecture, runtime_config.clone());

        let disassembly_started_at = Instant::now();
        Stderr::print_debug(
            &config,
            format!(
                "macho slice {}: creating disassembler for {}",
                slice_index, architecture
            ),
        );
        let disassembler = match Disassembler::new(
            architecture,
            image,
            executable_address_ranges.clone(),
            runtime_config.clone(),
        ) {
            Ok(disassembler) => disassembler,
            Err(error) => {
                eprintln!("{}", error);
                process::exit(1);
            }
        };

        Stderr::print_debug(
            &config,
            format!(
                "macho slice {}: starting disassembly with {} seed entrypoints",
                slice_index,
                entrypoints.len()
            ),
        );
        disassembler
            .disassemble(entrypoints, &mut cfg)
            .unwrap_or_else(|error| {
                eprintln!("{}", error);
                process::exit(1);
            });
        Stderr::print_debug(
            &config,
            format!(
                "macho slice {}: disassembly finished instructions={} blocks={} functions={}",
                slice_index,
                cfg.instructions.valid().iter().count(),
                cfg.blocks.valid().iter().count(),
                cfg.functions.valid().iter().count()
            ),
        );
        print_stage_timing(&config, "macho.disassemble", disassembly_started_at);

        let output_started_at = Instant::now();
        process_output(output.clone(), &cfg, &attributes, &function_symbols);
        print_stage_timing(&config, "macho.process_output", output_started_at);
    }
    print_stage_timing(&config, "macho.total", process_started_at);
}

fn main() {
    let startup_started_at = Instant::now();
    let args = Args::parse();

    validate_args(&args);

    let mut config = Config::new();

    let config_started_at = Instant::now();
    if args.config.is_some() {
        match Config::from_file(&args.config.clone().unwrap().to_string()) {
            Ok(result) => {
                config = result;
            }
            Err(error) => {
                eprintln!("{}", error);
                process::exit(1);
            }
        }
    } else {
        if config.from_default().is_err() {
            let _ = config.write_default();
        }
    }
    print_stage_timing(&config, "config.load", config_started_at);

    apply_cli_overrides(&args, &mut config);

    Stderr::print_debug(&config, "finished reading arguments and configuration");

    let thread_pool_started_at = Instant::now();
    ThreadPoolBuilder::new()
        .num_threads(config.resolved_threads())
        .build_global()
        .unwrap_or_else(|error| {
            eprintln!("{}", error);
            process::exit(1);
        });
    print_stage_timing(&config, "thread_pool.build", thread_pool_started_at);

    if args.architecture.is_none() {
        let magic_started_at = Instant::now();
        let format = Magic::from_file(args.input.clone()).unwrap_or_else(|error| {
            eprintln!("{}", error);
            process::exit(1);
        });
        print_stage_timing(&config, "magic.from_file", magic_started_at);
        match format {
            Magic::PE => {
                Stderr::print_debug(&config, "processing pe");
                process_pe(
                    &args,
                    args.input.clone(),
                    config.clone(),
                    args.tags.clone(),
                    args.output.clone(),
                    args.stdin,
                );
            }
            Magic::ELF => {
                Stderr::print_debug(&config, "processing elf");
                process_elf(
                    &args,
                    args.input.clone(),
                    config.clone(),
                    args.tags.clone(),
                    args.output.clone(),
                    args.stdin,
                );
            }
            Magic::MACHO => {
                Stderr::print_debug(&config, "processing macho");
                process_macho(
                    &args,
                    args.input.clone(),
                    config.clone(),
                    args.tags.clone(),
                    args.output.clone(),
                    args.stdin,
                );
            }
            _ => {
                eprintln!("unable to identify file format");
                process::exit(1);
            }
        }
    } else {
        let architecture = args.architecture.unwrap();
        match architecture {
            Architecture::ARM64 | Architecture::AMD64 | Architecture::I386 | Architecture::CIL => {
                Stderr::print_debug(&config, "processing code");
                process_code(
                    &args,
                    args.input.clone(),
                    config.clone(),
                    architecture,
                    args.output.clone(),
                );
            }
            _ => {
                eprintln!("unsupported architecture");
                process::exit(1);
            }
        }
    }

    print_stage_timing(&config, "binlex.total", startup_started_at);

    process::exit(0);
}

#[cfg(test)]
mod tests {
    use super::{Args, apply_cli_overrides};
    use binlex::Config;

    #[test]
    fn cli_processes_overrides_processor_process_count() {
        let args = Args {
            input: "input.bin".to_string(),
            output: None,
            stdin: false,
            architecture: None,
            config: None,
            threads: None,
            processes: Some(8),
            tags: None,
            minimal: false,
            debug: false,
            enable_instructions: false,
            enable_mmap_cache: false,
            mmap_directory: None,
            processors: None,
        };

        let mut config = Config::default();
        config.processors.processes = 2;

        apply_cli_overrides(&args, &mut config);

        assert_eq!(config.processors.processes, 8);
    }
}
