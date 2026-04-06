use crate::controlflow::{Graph, GraphSnapshot};
use crate::disassemblers::capstone::Disassembler;
use crate::disassemblers::cil::Disassembler as CILDisassembler;
use crate::formats::{ELF, File, MACHO, PE};
use crate::metadata::Attributes;
use crate::server::dto::AnalyzeRequest;
use crate::server::error::ServerError;
use crate::{Architecture, Config, Magic};
use base64::Engine;
use ring::digest::{SHA256, digest};
use std::collections::{BTreeMap, BTreeSet};
use tracing::info;

pub fn execute(config: &Config, request: AnalyzeRequest) -> Result<GraphSnapshot, ServerError> {
    let data = base64::engine::general_purpose::STANDARD
        .decode(&request.data)
        .map_err(|error| ServerError::processor(format!("invalid base64 payload: {}", error)))?;
    let mut analysis_config = config.clone();

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
    let corpora = normalize_corpora(&request.corpora);

    match selected_magic {
        Magic::PE => analyze_pe(
            &mut analysis_config,
            requested_architecture,
            data,
            selected_magic,
            corpora,
        ),
        Magic::ELF => analyze_elf(
            &mut analysis_config,
            requested_architecture,
            data,
            selected_magic,
            corpora,
        ),
        Magic::MACHO => analyze_macho(
            &mut analysis_config,
            requested_architecture,
            data,
            selected_magic,
            corpora,
        ),
        Magic::CODE => analyze_code(
            &mut analysis_config,
            requested_architecture,
            data,
            selected_magic,
            corpora,
        ),
        Magic::PNG => Err(ServerError::unsupported_media(
            "png inputs do not produce a control-flow graph".to_string(),
        )),
        Magic::UNKNOWN => Err(ServerError::unsupported_media(
            "unable to identify file format; provide magic override".to_string(),
        )),
    }
}

fn parse_magic(value: &str) -> Result<Option<Magic>, ServerError> {
    let magic = value
        .parse::<Magic>()
        .map_err(|error| ServerError::processor(error.to_string()))?;
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
        .map_err(|error| ServerError::processor(error.to_string()))
}

fn normalize_corpora(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn digest_hex(data: &[u8]) -> String {
    let digest = digest(&SHA256, data);
    crate::hex::encode(digest.as_ref())
}

fn collect_attributes(
    bytes: &[u8],
    architecture: Architecture,
    config: Config,
    magic: Magic,
) -> Attributes {
    let mut attributes = Attributes::new();
    let file = File::from_bytes(bytes.to_vec(), config.clone());
    if !config.general.minimal {
        attributes.push(file.attribute());
    }
    match magic {
        Magic::ELF => {
            if let Ok(elf) = ELF::from_bytes(bytes.to_vec(), config) {
                for symbol in elf.symbols().into_values() {
                    attributes.push(symbol.attribute());
                }
            }
        }
        Magic::MACHO => {
            if let Ok(macho) = MACHO::from_bytes(bytes.to_vec(), config) {
                for (slice_index, _) in macho.slices().enumerate() {
                    if macho.architecture(slice_index) != Some(architecture) {
                        continue;
                    }
                    for symbol in macho.symbols(slice_index).into_values() {
                        attributes.push(symbol.attribute());
                    }
                }
            }
        }
        Magic::PE => {
            let _ = PE::from_bytes(bytes.to_vec(), config);
        }
        _ => {}
    }
    attributes
}

fn finalize_graph(
    cfg: &mut Graph,
    data: &[u8],
    _attributes: &Attributes,
    corpora: &[String],
) -> Result<GraphSnapshot, ServerError> {
    let embeddings = cfg.config.processors.processor("embeddings");
    info!(
        "analyze finalize sha256={} corpora={:?} embeddings_enabled={} graph_enabled={} complete_enabled={}",
        digest_hex(data),
        corpora,
        embeddings
            .map(|processor| processor.enabled)
            .unwrap_or(false),
        embeddings
            .map(|processor| processor.graph.enabled)
            .unwrap_or(false),
        embeddings
            .map(|processor| processor.complete.enabled)
            .unwrap_or(false),
    );
    cfg.process()
        .map_err(|error| ServerError::processor(error.to_string()))?;
    Ok(cfg.snapshot())
}

#[cfg(test)]
mod tests {
    use crate::Magic;
    use crate::server::dto::AnalyzeRequest;
    use base64::Engine;
    use serde_json::Value;

    #[test]
    fn analyze_request_payload_has_no_config_field() {
        let request = AnalyzeRequest {
            data: base64::engine::general_purpose::STANDARD.encode([0xC3u8]),
            magic: Some(Magic::CODE.to_string()),
            architecture: Some("amd64".to_string()),
            corpora: vec!["default".to_string()],
        };
        let json: Value = serde_json::to_value(request).expect("request should serialize");
        assert!(json.get("config").is_none());
        assert_eq!(
            json.get("corpora")
                .and_then(Value::as_array)
                .map(Vec::len)
                .unwrap_or_default(),
            1
        );
    }
}

fn analyze_pe(
    config: &mut Config,
    requested_architecture: Option<Architecture>,
    data: Vec<u8>,
    magic: Magic,
    corpora: Vec<String>,
) -> Result<GraphSnapshot, ServerError> {
    let pe = PE::from_bytes(data.clone(), config.clone())
        .map_err(|error| ServerError::processor(format!("failed to parse pe image: {}", error)))?;
    let architecture = requested_architecture.unwrap_or(pe.architecture());
    if architecture == Architecture::UNKNOWN {
        return Err(ServerError::processor(
            "unsupported pe architecture".to_string(),
        ));
    }

    let mut mapped = pe
        .image()
        .map_err(|error| ServerError::processor(format!("failed to map pe image: {}", error)))?;
    let image = mapped
        .mmap()
        .map_err(|error| ServerError::processor(format!("failed to map pe image: {}", error)))?;

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
        .map_err(|error| ServerError::processor(error.to_string()))?;
        disassembler
            .disassemble(entrypoints, &mut cfg)
            .map_err(|error| ServerError::processor(error.to_string()))?;
    } else {
        let disassembler = Disassembler::new(
            architecture,
            image,
            executable_address_ranges,
            config.clone(),
        )
        .map_err(|error| ServerError::processor(error.to_string()))?;
        disassembler
            .disassemble(entrypoints, &mut cfg)
            .map_err(|error| ServerError::processor(error.to_string()))?;
    }

    let attributes = collect_attributes(&data, architecture, config.clone(), magic);
    finalize_graph(&mut cfg, &data, &attributes, &corpora)
}

fn analyze_elf(
    config: &mut Config,
    requested_architecture: Option<Architecture>,
    data: Vec<u8>,
    magic: Magic,
    corpora: Vec<String>,
) -> Result<GraphSnapshot, ServerError> {
    let elf = ELF::from_bytes(data.clone(), config.clone())
        .map_err(|error| ServerError::processor(format!("failed to parse elf image: {}", error)))?;
    let architecture = requested_architecture.unwrap_or(elf.architecture());
    if architecture == Architecture::UNKNOWN {
        return Err(ServerError::processor(
            "unsupported elf architecture".to_string(),
        ));
    }

    let mut mapped = elf
        .image()
        .map_err(|error| ServerError::processor(format!("failed to map elf image: {}", error)))?;
    let image = mapped
        .mmap()
        .map_err(|error| ServerError::processor(format!("failed to map elf image: {}", error)))?;

    let mut cfg = Graph::new(architecture, config.clone());
    let disassembler = Disassembler::new(
        architecture,
        image,
        elf.executable_virtual_address_ranges(),
        config.clone(),
    )
    .map_err(|error| ServerError::processor(error.to_string()))?;
    disassembler
        .disassemble(elf.entrypoint_virtual_addresses(), &mut cfg)
        .map_err(|error| ServerError::processor(error.to_string()))?;

    let attributes = collect_attributes(&data, architecture, config.clone(), magic);
    finalize_graph(&mut cfg, &data, &attributes, &corpora)
}

fn analyze_macho(
    config: &mut Config,
    requested_architecture: Option<Architecture>,
    data: Vec<u8>,
    magic: Magic,
    corpora: Vec<String>,
) -> Result<GraphSnapshot, ServerError> {
    let macho = MACHO::from_bytes(data.clone(), config.clone()).map_err(|error| {
        ServerError::processor(format!("failed to parse macho image: {}", error))
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
                return Err(ServerError::processor(
                    "architecture is required for multi-architecture macho analysis".to_string(),
                ));
            }
            unique_architectures.into_iter().next().ok_or_else(|| {
                ServerError::processor("unsupported macho architecture".to_string())
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
            ServerError::processor(format!("failed to map macho image: {}", error))
        })?;
        let image = mapped.mmap().map_err(|error| {
            ServerError::processor(format!("failed to map macho image: {}", error))
        })?;
        let mut cfg = Graph::new(architecture, config.clone());
        let disassembler = Disassembler::new(
            architecture,
            image,
            slice.executable_virtual_address_ranges(),
            config.clone(),
        )
        .map_err(|error| ServerError::processor(error.to_string()))?;
        disassembler
            .disassemble(slice.entrypoint_virtual_addresses(), &mut cfg)
            .map_err(|error| ServerError::processor(error.to_string()))?;
        if let Some(existing) = &mut merged_graph {
            existing.merge(&mut cfg);
        } else {
            merged_graph = Some(cfg);
        }
    }

    let mut graph = merged_graph.ok_or_else(|| {
        ServerError::processor("requested macho architecture not found".to_string())
    })?;
    let attributes = collect_attributes(&data, selected_architecture, config.clone(), magic);
    finalize_graph(&mut graph, &data, &attributes, &corpora)
}

fn analyze_code(
    config: &mut Config,
    requested_architecture: Option<Architecture>,
    data: Vec<u8>,
    magic: Magic,
    corpora: Vec<String>,
) -> Result<GraphSnapshot, ServerError> {
    let architecture = requested_architecture.ok_or_else(|| {
        ServerError::processor("architecture is required for code analysis".to_string())
    })?;

    if architecture == Architecture::UNKNOWN {
        return Err(ServerError::processor(
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
            .map_err(|error| ServerError::processor(error.to_string()))?;
            disassembler
                .disassemble(entrypoints, &mut cfg)
                .map_err(|error| ServerError::processor(error.to_string()))?;
        }
        Architecture::CIL => {
            let disassembler = CILDisassembler::new(
                architecture,
                &data,
                BTreeMap::<u64, u64>::new(),
                executable_address_ranges,
                config.clone(),
            )
            .map_err(|error| ServerError::processor(error.to_string()))?;
            disassembler
                .disassemble(entrypoints, &mut cfg)
                .map_err(|error| ServerError::processor(error.to_string()))?;
        }
        Architecture::UNKNOWN => {
            return Err(ServerError::processor(
                "unsupported architecture".to_string(),
            ));
        }
    }

    let attributes = collect_attributes(&data, architecture, config.clone(), magic);
    finalize_graph(&mut cfg, &data, &attributes, &corpora)
}
