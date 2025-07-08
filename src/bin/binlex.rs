//                    GNU LESSER GENERAL PUBLIC LICENSE
//                        Version 3, 29 June 2007
//
//  Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>
//  Everyone is permitted to copy and distribute verbatim copies
//  of this license document, but changing it is not allowed.
//
//
//   This version of the GNU Lesser General Public License incorporates
// the terms and conditions of version 3 of the GNU General Public
// License, supplemented by the additional permissions listed below.
//
//   0. Additional Definitions.
//
//   As used herein, "this License" refers to version 3 of the GNU Lesser
// General Public License, and the "GNU GPL" refers to version 3 of the GNU
// General Public License.
//
//   "The Library" refers to a covered work governed by this License,
// other than an Application or a Combined Work as defined below.
//
//   An "Application" is any work that makes use of an interface provided
// by the Library, but which is not otherwise based on the Library.
// Defining a subclass of a class defined by the Library is deemed a mode
// of using an interface provided by the Library.
//
//   A "Combined Work" is a work produced by combining or linking an
// Application with the Library.  The particular version of the Library
// with which the Combined Work was made is also called the "Linked
// Version".
//
//   The "Minimal Corresponding Source" for a Combined Work means the
// Corresponding Source for the Combined Work, excluding any source code
// for portions of the Combined Work that, considered in isolation, are
// based on the Application, and not on the Linked Version.
//
//   The "Corresponding Application Code" for a Combined Work means the
// object code and/or source code for the Application, including any data
// and utility programs needed for reproducing the Combined Work from the
// Application, but excluding the System Libraries of the Combined Work.
//
//   1. Exception to Section 3 of the GNU GPL.
//
//   You may convey a covered work under sections 3 and 4 of this License
// without being bound by section 3 of the GNU GPL.
//
//   2. Conveying Modified Versions.
//
//   If you modify a copy of the Library, and, in your modifications, a
// facility refers to a function or data to be supplied by an Application
// that uses the facility (other than as an argument passed when the
// facility is invoked), then you may convey a copy of the modified
// version:
//
//    a) under this License, provided that you make a good faith effort to
//    ensure that, in the event an Application does not supply the
//    function or data, the facility still operates, and performs
//    whatever part of its purpose remains meaningful, or
//
//    b) under the GNU GPL, with none of the additional permissions of
//    this License applicable to that copy.
//
//   3. Object Code Incorporating Material from Library Header Files.
//
//   The object code form of an Application may incorporate material from
// a header file that is part of the Library.  You may convey such object
// code under terms of your choice, provided that, if the incorporated
// material is not limited to numerical parameters, data structure
// layouts and accessors, or small macros, inline functions and templates
// (ten or fewer lines in length), you do both of the following:
//
//    a) Give prominent notice with each copy of the object code that the
//    Library is used in it and that the Library and its use are
//    covered by this License.
//
//    b) Accompany the object code with a copy of the GNU GPL and this license
//    document.
//
//   4. Combined Works.
//
//   You may convey a Combined Work under terms of your choice that,
// taken together, effectively do not restrict modification of the
// portions of the Library contained in the Combined Work and reverse
// engineering for debugging such modifications, if you also do each of
// the following:
//
//    a) Give prominent notice with each copy of the Combined Work that
//    the Library is used in it and that the Library and its use are
//    covered by this License.
//
//    b) Accompany the Combined Work with a copy of the GNU GPL and this license
//    document.
//
//    c) For a Combined Work that displays copyright notices during
//    execution, include the copyright notice for the Library among
//    these notices, as well as a reference directing the user to the
//    copies of the GNU GPL and this license document.
//
//    d) Do one of the following:
//
//        0) Convey the Minimal Corresponding Source under the terms of this
//        License, and the Corresponding Application Code in a form
//        suitable for, and under terms that permit, the user to
//        recombine or relink the Application with a modified version of
//        the Linked Version to produce a modified Combined Work, in the
//        manner specified by section 6 of the GNU GPL for conveying
//        Corresponding Source.
//
//        1) Use a suitable shared library mechanism for linking with the
//        Library.  A suitable mechanism is one that (a) uses at run time
//        a copy of the Library already present on the user's computer
//        system, and (b) will operate properly with a modified version
//        of the Library that is interface-compatible with the Linked
//        Version.
//
//    e) Provide Installation Information, but only if you would otherwise
//    be required to provide such information under section 6 of the
//    GNU GPL, and only to the extent that such information is
//    necessary to install and execute a modified version of the
//    Combined Work produced by recombining or relinking the
//    Application with a modified version of the Linked Version. (If
//    you use option 4d0, the Installation Information must accompany
//    the Minimal Corresponding Source and Corresponding Application
//    Code. If you use option 4d1, you must provide the Installation
//    Information in the manner specified by section 6 of the GNU GPL
//    for conveying Corresponding Source.)
//
//   5. Combined Libraries.
//
//   You may place library facilities that are a work based on the
// Library side by side in a single library together with other library
// facilities that are not Applications and are not covered by this
// License, and convey such a combined library under terms of your
// choice, if you do both of the following:
//
//    a) Accompany the combined library with a copy of the same work based
//    on the Library, uncombined with any other library facilities,
//    conveyed under the terms of this License.
//
//    b) Give prominent notice with the combined library that part of it
//    is a work based on the Library, and explaining where to find the
//    accompanying uncombined form of the same work.
//
//   6. Revised Versions of the GNU Lesser General Public License.
//
//   The Free Software Foundation may publish revised and/or new versions
// of the GNU Lesser General Public License from time to time. Such new
// versions will be similar in spirit to the present version, but may
// differ in detail to address new problems or concerns.
//
//   Each version is given a distinguishing version number. If the
// Library as you received it specifies that a certain numbered version
// of the GNU Lesser General Public License "or any later version"
// applies to it, you have the option of following the terms and
// conditions either of that published version or of any later version
// published by the Free Software Foundation. If the Library as you
// received it does not specify a version number of the GNU Lesser
// General Public License, you may choose any version of the GNU Lesser
// General Public License ever published by the Free Software Foundation.
//
//   If the Library as you received it specifies that a proxy can decide
// whether future versions of the GNU Lesser General Public License shall
// apply, that proxy's public statement of acceptance of any version is
// permanent authorization for you to choose that version for the
// Library.

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
