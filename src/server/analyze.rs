use crate::Architecture;
use crate::Config;
use crate::Magic;
use crate::controlflow::{Graph, GraphSnapshot};
use crate::disassemblers::capstone::Disassembler;
use crate::disassemblers::cil::Disassembler as CILDisassembler;
use crate::formats::{ELF, File, MACHO, PE};
use crate::metadata::Attributes;
use crate::server::dto::AnalyzeRequest;
use crate::server::error::ServerError;
use base64::Engine;
use std::collections::{BTreeMap, BTreeSet};

pub fn execute(config: &Config, request: AnalyzeRequest) -> Result<GraphSnapshot, ServerError> {
    let data = base64::engine::general_purpose::STANDARD
        .decode(&request.data)
        .map_err(|error| ServerError::Processor(format!("invalid base64 payload: {}", error)))?;
    let analysis_config = request.config.unwrap_or_else(|| config.clone());

    let detected_magic = Magic::from_bytes(&data);
    let requested_magic = request
        .magic
        .as_deref()
        .map(parse_magic)
        .transpose()?
        .flatten();
    let selected_magic = requested_magic.unwrap_or(detected_magic);
    let requested_architecture = request
        .architecture
        .as_deref()
        .map(parse_architecture)
        .transpose()?
        .flatten();

    let file = File::from_bytes(data.clone(), analysis_config.clone());
    let mut attributes = Attributes::new();
    if !analysis_config.general.minimal {
        attributes.push(file.attribute());
    }

    match selected_magic {
        Magic::PE => analyze_pe(&analysis_config, requested_architecture, data, attributes),
        Magic::ELF => analyze_elf(&analysis_config, requested_architecture, data, attributes),
        Magic::MACHO => analyze_macho(&analysis_config, requested_architecture, data, attributes),
        Magic::CODE => analyze_code(&analysis_config, requested_architecture, data, attributes),
        Magic::PNG => Err(ServerError::Processor(
            "png inputs do not produce a control-flow graph".to_string(),
        )),
        Magic::UNKNOWN => Err(ServerError::Processor(
            "unable to identify file format; provide magic override".to_string(),
        )),
    }
}

fn parse_magic(value: &str) -> Result<Option<Magic>, ServerError> {
    let magic = value
        .parse::<Magic>()
        .map_err(|error| ServerError::Processor(error.to_string()))?;
    Ok(match magic {
        Magic::UNKNOWN => None,
        other => Some(other),
    })
}

fn parse_architecture(value: &str) -> Result<Option<Architecture>, ServerError> {
    if value.eq_ignore_ascii_case("unknown") {
        return Ok(None);
    }
    Architecture::from_string(value)
        .map(Some)
        .map_err(|error| ServerError::Processor(error.to_string()))
}

fn finalize_graph(cfg: &Graph, _attributes: &Attributes) -> Result<GraphSnapshot, ServerError> {
    cfg.process()
        .map_err(|error| ServerError::Processor(error.to_string()))?;
    Ok(cfg.snapshot())
}

fn analyze_pe(
    config: &Config,
    requested_architecture: Option<Architecture>,
    data: Vec<u8>,
    attributes: Attributes,
) -> Result<GraphSnapshot, ServerError> {
    let pe = PE::from_bytes(data, config.clone())
        .map_err(|error| ServerError::Processor(format!("failed to parse pe image: {}", error)))?;
    let architecture = requested_architecture.unwrap_or(pe.architecture());
    if architecture == Architecture::UNKNOWN {
        return Err(ServerError::Processor(
            "unsupported pe architecture".to_string(),
        ));
    }

    let mut mapped = pe
        .image()
        .map_err(|error| ServerError::Processor(format!("failed to map pe image: {}", error)))?;
    let image = mapped
        .mmap()
        .map_err(|error| ServerError::Processor(format!("failed to map pe image: {}", error)))?;

    let executable_address_ranges = if pe.is_dotnet() {
        pe.dotnet_executable_virtual_address_ranges()
    } else {
        pe.executable_virtual_address_ranges()
    };

    let mut entrypoints = BTreeSet::<u64>::new();
    if pe.is_dotnet() {
        entrypoints.extend(pe.dotnet_entrypoint_virtual_addresses());
    } else {
        entrypoints.extend(pe.entrypoint_virtual_addresses());
    }

    let mut cfg = Graph::new(architecture, config.clone());
    if pe.is_dotnet() {
        let disassembler = CILDisassembler::new(
            architecture,
            image,
            pe.dotnet_metadata_token_virtual_addresses(),
            executable_address_ranges,
            config.clone(),
        )
        .map_err(|error| ServerError::Processor(error.to_string()))?;
        disassembler
            .disassemble(entrypoints, &mut cfg)
            .map_err(|error| ServerError::Processor(error.to_string()))?;
    } else {
        let disassembler = Disassembler::new(
            architecture,
            image,
            executable_address_ranges,
            config.clone(),
        )
        .map_err(|error| ServerError::Processor(error.to_string()))?;
        disassembler
            .disassemble(entrypoints, &mut cfg)
            .map_err(|error| ServerError::Processor(error.to_string()))?;
    }

    finalize_graph(&cfg, &attributes)
}

fn analyze_elf(
    config: &Config,
    requested_architecture: Option<Architecture>,
    data: Vec<u8>,
    attributes: Attributes,
) -> Result<GraphSnapshot, ServerError> {
    let elf = ELF::from_bytes(data, config.clone())
        .map_err(|error| ServerError::Processor(format!("failed to parse elf image: {}", error)))?;
    let architecture = requested_architecture.unwrap_or(elf.architecture());
    if architecture == Architecture::UNKNOWN {
        return Err(ServerError::Processor(
            "unsupported elf architecture".to_string(),
        ));
    }

    let mut mapped = elf
        .image()
        .map_err(|error| ServerError::Processor(format!("failed to map elf image: {}", error)))?;
    let image = mapped
        .mmap()
        .map_err(|error| ServerError::Processor(format!("failed to map elf image: {}", error)))?;

    let mut cfg = Graph::new(architecture, config.clone());
    let disassembler = Disassembler::new(
        architecture,
        image,
        elf.executable_virtual_address_ranges(),
        config.clone(),
    )
    .map_err(|error| ServerError::Processor(error.to_string()))?;
    disassembler
        .disassemble(elf.entrypoint_virtual_addresses(), &mut cfg)
        .map_err(|error| ServerError::Processor(error.to_string()))?;

    finalize_graph(&cfg, &attributes)
}

fn analyze_macho(
    config: &Config,
    requested_architecture: Option<Architecture>,
    data: Vec<u8>,
    attributes: Attributes,
) -> Result<GraphSnapshot, ServerError> {
    let macho = MACHO::from_bytes(data, config.clone()).map_err(|error| {
        ServerError::Processor(format!("failed to parse macho image: {}", error))
    })?;

    let slices: Vec<_> = macho.slices().collect();
    let available_architectures: Vec<Architecture> = slices
        .iter()
        .filter_map(|slice| slice.architecture())
        .filter(|architecture| *architecture != Architecture::UNKNOWN)
        .collect();
    let selected_architecture = match requested_architecture {
        Some(architecture) => architecture,
        None => {
            let mut unique_architectures = Vec::new();
            for architecture in available_architectures {
                if !unique_architectures.contains(&architecture) {
                    unique_architectures.push(architecture);
                }
            }
            if unique_architectures.len() > 1 {
                return Err(ServerError::Processor(
                    "architecture is required for multi-architecture macho analysis".to_string(),
                ));
            }
            unique_architectures.into_iter().next().ok_or_else(|| {
                ServerError::Processor("unsupported macho architecture".to_string())
            })?
        }
    };

    let mut merged_graph: Option<Graph> = None;

    for slice in slices {
        let Some(detected_architecture) = slice.architecture() else {
            continue;
        };
        if detected_architecture == Architecture::UNKNOWN {
            continue;
        }
        if detected_architecture != selected_architecture {
            continue;
        }
        let architecture = selected_architecture;
        let mut mapped = slice.image().map_err(|error| {
            ServerError::Processor(format!("failed to map macho image: {}", error))
        })?;
        let image = mapped.mmap().map_err(|error| {
            ServerError::Processor(format!("failed to map macho image: {}", error))
        })?;
        let mut cfg = Graph::new(architecture, config.clone());
        let disassembler = Disassembler::new(
            architecture,
            image,
            slice.executable_virtual_address_ranges(),
            config.clone(),
        )
        .map_err(|error| ServerError::Processor(error.to_string()))?;
        disassembler
            .disassemble(slice.entrypoint_virtual_addresses(), &mut cfg)
            .map_err(|error| ServerError::Processor(error.to_string()))?;
        if let Some(existing) = &mut merged_graph {
            existing.merge(&mut cfg);
        } else {
            merged_graph = Some(cfg);
        }
    }

    let graph = merged_graph.ok_or_else(|| {
        ServerError::Processor("requested macho architecture not found".to_string())
    })?;
    finalize_graph(&graph, &attributes)
}

fn analyze_code(
    config: &Config,
    requested_architecture: Option<Architecture>,
    data: Vec<u8>,
    attributes: Attributes,
) -> Result<GraphSnapshot, ServerError> {
    let architecture = requested_architecture.ok_or_else(|| {
        ServerError::Processor("architecture is required for code analysis".to_string())
    })?;

    if architecture == Architecture::UNKNOWN {
        return Err(ServerError::Processor(
            "unsupported architecture".to_string(),
        ));
    }

    let mut executable_address_ranges = BTreeMap::<u64, u64>::new();
    executable_address_ranges.insert(0, data.len() as u64);
    let mut entrypoints = BTreeSet::<u64>::new();
    entrypoints.insert(0);

    let mut cfg = Graph::new(architecture, config.clone());
    match architecture {
        Architecture::AMD64 | Architecture::I386 => {
            let disassembler = Disassembler::new(
                architecture,
                &data,
                executable_address_ranges,
                config.clone(),
            )
            .map_err(|error| ServerError::Processor(error.to_string()))?;
            disassembler
                .disassemble(entrypoints, &mut cfg)
                .map_err(|error| ServerError::Processor(error.to_string()))?;
        }
        Architecture::CIL => {
            let disassembler = CILDisassembler::new(
                architecture,
                &data,
                BTreeMap::<u64, u64>::new(),
                executable_address_ranges,
                config.clone(),
            )
            .map_err(|error| ServerError::Processor(error.to_string()))?;
            disassembler
                .disassemble(entrypoints, &mut cfg)
                .map_err(|error| ServerError::Processor(error.to_string()))?;
        }
        Architecture::UNKNOWN => {
            return Err(ServerError::Processor(
                "unsupported architecture".to_string(),
            ));
        }
    }

    finalize_graph(&cfg, &attributes)
}
