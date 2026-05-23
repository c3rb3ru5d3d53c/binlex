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
use binlex::Configuration;
use binlex::Magic;
use binlex::VERSION;
use binlex::config::RAYON_WORKER_STACK_SIZE;
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
use binlex::metadata::Attributes;
use binlex::metadata::Tag;
use binlex::processor::{ProcessorTarget, apply_output};
use clap::Parser;
use rayon::ThreadPoolBuilder;
use rayon::prelude::*;
use serde_json::json;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashSet;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};
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

fn apply_cli_overrides(args: &Args, config: &mut Configuration) {
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

fn print_stage_timing(config: &Configuration, stage: &str, started_at: Instant) {
    if config.debug {
        Stderr::print(format!(
            "[timing] {}: {:.3} ms",
            stage,
            started_at.elapsed().as_secs_f64() * 1000.0
        ));
    }
}

fn entity_attributes(
    attributes: &Attributes,
    function_symbols: &BTreeMap<u64, Symbol>,
    address: u64,
) -> Attributes {
    let mut result = Attributes::new();
    if let Some(symbol) = function_symbols.get(&address) {
        result.push(symbol.attribute());
    }
    for attribute in &attributes.values {
        result.push(attribute.clone());
    }
    result
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
            let offset = value
                .get("file_offset")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let address = value.get("virtual_address").and_then(|v| v.as_u64());
            let relative_virtual_address = value
                .get("relative_virtual_address")
                .and_then(|v| v.as_u64());
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
                offset,
                Some(address.unwrap()),
                relative_virtual_address,
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
            let offset = value
                .get("file_offset")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let address = value.get("virtual_address").and_then(|v| v.as_u64());
            let relative_virtual_address = value
                .get("relative_virtual_address")
                .and_then(|v| v.as_u64());
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
                offset,
                Some(address.unwrap()),
                relative_virtual_address,
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
            let offset = value
                .get("file_offset")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let address = value.get("virtual_address").and_then(|v| v.as_u64());
            let relative_virtual_address = value
                .get("relative_virtual_address")
                .and_then(|v| v.as_u64());
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
                offset,
                Some(address.unwrap()),
                relative_virtual_address,
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
    enum OutputWriter {
        Stdout(BufWriter<io::Stdout>),
        File(BufWriter<File>),
    }

    impl OutputWriter {
        fn write_line(&mut self, line: &str) {
            let result = match self {
                OutputWriter::Stdout(writer) => writeln!(writer, "{}", line),
                OutputWriter::File(writer) => writeln!(writer, "{}", line),
            };
            if let Err(error) = result {
                eprintln!("{}", error);
                std::process::exit(1);
            }
        }

        fn flush(&mut self) {
            let result = match self {
                OutputWriter::Stdout(writer) => writer.flush(),
                OutputWriter::File(writer) => writer.flush(),
            };
            if let Err(error) = result {
                eprintln!("{}", error);
                std::process::exit(1);
            }
        }
    }

    let mut writer = match output {
        Some(output_file) => match File::create(output_file) {
            Ok(file) => OutputWriter::File(BufWriter::new(file)),
            Err(error) => {
                eprintln!("{}", error);
                std::process::exit(1);
            }
        },
        None => OutputWriter::Stdout(BufWriter::new(io::stdout())),
    };

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
        let process_instructions_started_at = Instant::now();
        let _ = cfg.process_instructions();
        print_stage_timing(
            &cfg.config,
            "cli.process_output.instructions.process",
            process_instructions_started_at,
        );
        let instruction_addresses = cfg
            .instructions
            .valid()
            .iter()
            .map(|entry| *entry)
            .collect::<Vec<_>>();
        let materialize_instructions_started_at = Instant::now();
        let instruction_lines = instruction_addresses
            .into_par_iter()
            .filter_map(|address| {
                let instruction = Instruction::new(address, cfg).ok()?;
                let instruction_attributes =
                    entity_attributes(attributes, function_symbols, instruction.address);
                let mut raw = instruction.process_with_attributes(instruction_attributes);
                if let Some(outputs) =
                    cfg.processor_outputs(ProcessorTarget::Instruction, instruction.address)
                {
                    for (processor_name, output) in &outputs {
                        apply_output(
                            raw.processors.get_or_insert_with(Default::default),
                            processor_name,
                            output,
                        );
                    }
                }
                serde_json::to_string(&raw).ok()
            })
            .collect::<Vec<_>>();
        print_stage_timing(
            &cfg.config,
            "cli.process_output.instructions.materialize",
            materialize_instructions_started_at,
        );
        let write_instructions_started_at = Instant::now();
        for json in instruction_lines {
            writer.write_line(&json);
        }
        writer.flush();
        print_stage_timing(
            &cfg.config,
            "cli.process_output.instructions.write",
            write_instructions_started_at,
        );
    }

    if cfg.config.blocks.enabled {
        let process_blocks_started_at = Instant::now();
        let _ = cfg.process_blocks();
        print_stage_timing(
            &cfg.config,
            "cli.process_output.blocks.process",
            process_blocks_started_at,
        );
        Stderr::print_debug(
            &cfg.config,
            format!(
                "block processor outputs attached to {} blocks",
                block_output_count
            ),
        );
        let block_addresses = cfg
            .blocks
            .valid()
            .iter()
            .map(|entry| *entry)
            .collect::<Vec<_>>();
        let materialize_blocks_started_at = Instant::now();
        let block_lines = block_addresses
            .into_par_iter()
            .filter_map(|address| {
                let block = Block::new(address, cfg).ok()?;
                let block_attributes =
                    entity_attributes(attributes, function_symbols, block.address);
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
                serde_json::to_string(&raw).ok()
            })
            .collect::<Vec<_>>();
        print_stage_timing(
            &cfg.config,
            "cli.process_output.blocks.materialize",
            materialize_blocks_started_at,
        );
        let write_blocks_started_at = Instant::now();
        for json in block_lines {
            writer.write_line(&json);
        }
        writer.flush();
        print_stage_timing(
            &cfg.config,
            "cli.process_output.blocks.write",
            write_blocks_started_at,
        );
    }

    if cfg.config.functions.enabled {
        let process_functions_started_at = Instant::now();
        let _ = cfg.process_functions();
        print_stage_timing(
            &cfg.config,
            "cli.process_output.functions.process",
            process_functions_started_at,
        );
        Stderr::print_debug(
            &cfg.config,
            format!(
                "function processor outputs attached to {} functions",
                function_output_count
            ),
        );
        let function_addresses = cfg
            .functions
            .valid()
            .iter()
            .map(|entry| *entry)
            .collect::<Vec<_>>();
        let debug = cfg.config.debug;
        let function_new_nanos = AtomicU64::new(0);
        let function_attributes_nanos = AtomicU64::new(0);
        let function_process_nanos = AtomicU64::new(0);
        let function_processor_output_nanos = AtomicU64::new(0);
        let function_serialize_nanos = AtomicU64::new(0);
        let materialize_functions_started_at = Instant::now();
        let function_lines = function_addresses
            .into_par_iter()
            .filter_map(|address| {
                let function_new_started_at = debug.then(Instant::now);
                let function = Function::new(address, cfg).ok()?;
                if let Some(started_at) = function_new_started_at {
                    function_new_nanos
                        .fetch_add(started_at.elapsed().as_nanos() as u64, Ordering::Relaxed);
                }
                let function_attributes_started_at = debug.then(Instant::now);
                let function_attributes =
                    entity_attributes(attributes, function_symbols, function.address);
                if let Some(started_at) = function_attributes_started_at {
                    function_attributes_nanos
                        .fetch_add(started_at.elapsed().as_nanos() as u64, Ordering::Relaxed);
                }
                let function_process_started_at = debug.then(Instant::now);
                let mut raw = function.process_with_attributes(function_attributes);
                if let Some(started_at) = function_process_started_at {
                    function_process_nanos
                        .fetch_add(started_at.elapsed().as_nanos() as u64, Ordering::Relaxed);
                }
                let function_processor_output_started_at = debug.then(Instant::now);
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
                if let Some(started_at) = function_processor_output_started_at {
                    function_processor_output_nanos
                        .fetch_add(started_at.elapsed().as_nanos() as u64, Ordering::Relaxed);
                }
                let function_serialize_started_at = debug.then(Instant::now);
                let json = serde_json::to_string(&raw).ok();
                if let Some(started_at) = function_serialize_started_at {
                    function_serialize_nanos
                        .fetch_add(started_at.elapsed().as_nanos() as u64, Ordering::Relaxed);
                }
                json
            })
            .collect::<Vec<_>>();
        print_stage_timing(
            &cfg.config,
            "cli.process_output.functions.materialize",
            materialize_functions_started_at,
        );
        if debug {
            Stderr::print(format!(
                "[timing] cli.process_output.functions.breakdown count={} new={:.3} ms attributes={:.3} ms process={:.3} ms processor_outputs={:.3} ms serialize={:.3} ms",
                function_lines.len(),
                function_new_nanos.load(Ordering::Relaxed) as f64 / 1_000_000.0,
                function_attributes_nanos.load(Ordering::Relaxed) as f64 / 1_000_000.0,
                function_process_nanos.load(Ordering::Relaxed) as f64 / 1_000_000.0,
                function_processor_output_nanos.load(Ordering::Relaxed) as f64 / 1_000_000.0,
                function_serialize_nanos.load(Ordering::Relaxed) as f64 / 1_000_000.0,
            ));
        }
        let write_functions_started_at = Instant::now();
        for json in function_lines {
            writer.write_line(&json);
        }
        print_stage_timing(
            &cfg.config,
            "cli.process_output.functions.write",
            write_functions_started_at,
        );
    }

    writer.flush();
}

fn process_pe(
    _args: &Args,
    input: String,
    config: Configuration,
    tags: Option<Vec<String>>,
    output: Option<String>,
    read_stdin: bool,
) {
    let process_started_at = Instant::now();
    let mut attributes = Attributes::new();
    let input_bytes = if read_stdin {
        Stdin::bytes().unwrap_or_else(|error| {
            eprintln!("failed to read pe bytes from stdin: {}", error);
            process::exit(1);
        })
    } else {
        std::fs::read(&input).unwrap_or_else(|error| {
            eprintln!("failed to read pe bytes: {}", error);
            process::exit(1);
        })
    };

    let pe_started_at = Instant::now();
    let pe = match PE::new(input_bytes, config.clone()) {
        Ok(pe) => pe,
        Err(error) => {
            eprintln!("failed to parse pe bytes: {}", error);
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
    let image_base = mapped_file.base();

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

    let runtime_config = config.clone();
    let mut cfg = Graph::new(pe.architecture(), runtime_config.clone());

    if !pe.is_dotnet() {
        Stderr::print_debug(&config, "starting pe disassembler");
        let disassembly_started_at = Instant::now();

        let disassembler = match Disassembler::new_with_image_base(
            pe.architecture(),
            image,
            image_base,
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

        let disassembler = match CILDisassembler::new_with_image_base(
            pe.architecture(),
            image,
            image_base,
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
            .disassemble(
                entrypoints.clone(),
                pe.dotnet_metadata_token_virtual_addresses().clone(),
                &mut cfg,
            )
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
    config: Configuration,
    tags: Option<Vec<String>>,
    output: Option<String>,
    read_stdin: bool,
) {
    let process_started_at = Instant::now();
    let mut attributes = Attributes::new();
    let input_bytes = if read_stdin {
        Stdin::bytes().unwrap_or_else(|error| {
            eprintln!("failed to read elf bytes from stdin: {}", error);
            process::exit(1);
        })
    } else {
        std::fs::read(&input).unwrap_or_else(|error| {
            eprintln!("failed to read elf bytes: {}", error);
            process::exit(1);
        })
    };

    let elf_started_at = Instant::now();
    let elf = ELF::new(input_bytes, config.clone()).unwrap_or_else(|error| {
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
    config: Configuration,
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
                .disassemble(entrypoints, BTreeMap::<u64, u64>::new(), &mut cfg)
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
    config: Configuration,
    tags: Option<Vec<String>>,
    output: Option<String>,
    read_stdin: bool,
) {
    let process_started_at = Instant::now();
    let mut attributes = Attributes::new();
    let input_bytes = if read_stdin {
        Stdin::bytes().unwrap_or_else(|error| {
            eprintln!("failed to read macho bytes from stdin: {}", error);
            process::exit(1);
        })
    } else {
        std::fs::read(&input).unwrap_or_else(|error| {
            eprintln!("failed to read macho bytes: {}", error);
            process::exit(1);
        })
    };

    let macho_started_at = Instant::now();
    let macho = MACHO::new(input_bytes, config.clone()).unwrap_or_else(|error| {
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

    let mut config = Configuration::new();

    let config_started_at = Instant::now();
    if args.config.is_some() {
        match Configuration::from_file(&args.config.clone().unwrap().to_string()) {
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
        .stack_size(RAYON_WORKER_STACK_SIZE)
        .build_global()
        .unwrap_or_else(|error| {
            eprintln!("{}", error);
            process::exit(1);
        });
    print_stage_timing(&config, "thread_pool.build", thread_pool_started_at);

    if args.architecture.is_none() {
        let magic_started_at = Instant::now();
        let input_bytes = std::fs::read(&args.input).unwrap_or_else(|error| {
            eprintln!("failed to read input bytes for magic detection: {}", error);
            process::exit(1);
        });
        let format = Magic::new(&input_bytes);
        print_stage_timing(&config, "magic.new", magic_started_at);
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
    use binlex::Configuration;

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

        let mut config = Configuration::default();
        config.processors.processes = 2;

        apply_cli_overrides(&args, &mut config);

        assert_eq!(config.processors.processes, 8);
    }
}
