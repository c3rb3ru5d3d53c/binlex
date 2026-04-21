use crate::controlflow::Graph;
use crate::disassemblers::capstone::Disassembler;
use crate::disassemblers::cil::Disassembler as CILDisassembler;
use crate::formats::{ELF, File, MACHO, PE};
use crate::indexing::Collection;
use crate::metadata::Attributes;
use crate::server::dto::{AnalyzeRequest, AnalyzeResponse, AnalyzeSelectedVectors};
use crate::server::error::ServerError;
use crate::{Architecture, Config, Magic};
use base64::Engine;
use ring::digest::{SHA256, digest};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;
use tracing::info;

pub fn execute(config: &Config, request: AnalyzeRequest) -> Result<AnalyzeResponse, ServerError> {
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
    let collections = normalize_collections(&request.collections);

    match selected_magic {
        Magic::PE => analyze_pe(
            &mut analysis_config,
            requested_architecture,
            data,
            selected_magic,
            corpora,
            collections,
        ),
        Magic::ELF => analyze_elf(
            &mut analysis_config,
            requested_architecture,
            data,
            selected_magic,
            corpora,
            collections,
        ),
        Magic::MACHO => analyze_macho(
            &mut analysis_config,
            requested_architecture,
            data,
            selected_magic,
            corpora,
            collections,
        ),
        Magic::CODE => analyze_code(
            &mut analysis_config,
            requested_architecture,
            data,
            selected_magic,
            corpora,
            collections,
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

fn normalize_collections(values: &[Collection]) -> BTreeSet<Collection> {
    if values.is_empty() {
        Collection::all().iter().copied().collect()
    } else {
        values.iter().copied().collect()
    }
}

fn digest_hex(data: &[u8]) -> String {
    let digest = digest(&SHA256, data);
    crate::hex::encode(digest.as_ref())
}

fn selector_value<'a>(
    value: &'a serde_json::Value,
    selector: &str,
) -> Option<&'a serde_json::Value> {
    let mut current = value;
    for part in selector.split('.') {
        if part.is_empty() {
            return None;
        }
        let mut remainder = part;
        let key_end = remainder.find('[').unwrap_or(remainder.len());
        if key_end > 0 {
            current = current.get(&remainder[..key_end])?;
            remainder = &remainder[key_end..];
        }
        while !remainder.is_empty() {
            let after_open = remainder.strip_prefix('[')?;
            let close = after_open.find(']')?;
            let index = after_open[..close].parse::<usize>().ok()?;
            current = current.get(index)?;
            remainder = &after_open[close + 1..];
        }
    }
    Some(current)
}

fn selector_vector(value: &serde_json::Value, selector: &str) -> Option<Vec<f32>> {
    let vector = selector_value(value, selector)?.as_array()?;
    vector
        .iter()
        .map(|value| value.as_f64().map(|item| item as f32))
        .collect()
}

fn selected_vector_selector(config: &Config) -> Option<&'static str> {
    if config.instructions.embeddings.llvm.enabled
        || config.blocks.embeddings.llvm.enabled
        || config.functions.embeddings.llvm.enabled
    {
        Some("embeddings.llvm.vector")
    } else {
        None
    }
}

fn collect_selected_vectors(
    graph: &Graph,
    selector: Option<&str>,
    collections: &BTreeSet<Collection>,
) -> Result<AnalyzeSelectedVectors, ServerError> {
    let Some(selector) = selector else {
        return Ok(AnalyzeSelectedVectors::default());
    };
    let mut selected = AnalyzeSelectedVectors::default();
    if collections.contains(&Collection::Instruction)
        && graph.config.instructions.embeddings.llvm.enabled
    {
        for instruction in graph.instructions() {
            let value = serde_json::to_value(instruction.process())
                .map_err(|error| ServerError::processor(error.to_string()))?;
            if let Some(vector) = selector_vector(&value, selector) {
                selected.instructions.insert(instruction.address, vector);
            }
        }
    }
    if collections.contains(&Collection::Block) && graph.config.blocks.embeddings.llvm.enabled {
        for block in graph.blocks() {
            let value = serde_json::to_value(block.process())
                .map_err(|error| ServerError::processor(error.to_string()))?;
            if let Some(vector) = selector_vector(&value, selector) {
                selected.blocks.insert(block.address(), vector);
            }
        }
    }
    if collections.contains(&Collection::Function) && graph.config.functions.embeddings.llvm.enabled
    {
        for function in graph.functions() {
            let value = serde_json::to_value(function.process())
                .map_err(|error| ServerError::processor(error.to_string()))?;
            if let Some(vector) = selector_vector(&value, selector) {
                selected.functions.insert(function.address, vector);
            }
        }
    }
    Ok(selected)
}

fn collect_attributes(
    bytes: &[u8],
    architecture: Architecture,
    config: Config,
    magic: Magic,
) -> Attributes {
    let mut attributes = Attributes::new();
    let file = File::from_bytes(bytes.to_vec(), config.clone());
    if !config.minimal {
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
                    if macho.architecture(slice_index) != architecture {
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
    collections: &BTreeSet<Collection>,
) -> Result<AnalyzeResponse, ServerError> {
    info!(
        "analyze finalize sha256={} corpora={:?} function_embeddings_enabled={} embedding_dimensions={} embedding_device={}",
        digest_hex(data),
        corpora,
        cfg.config.functions.embeddings.llvm.enabled,
        cfg.config.embeddings.llvm.dimensions,
        cfg.config.embeddings.llvm.device,
    );
    let total_started_at = Instant::now();
    cfg.process()
        .map_err(|error| ServerError::processor(error.to_string()))?;
    let selector_started_at = Instant::now();
    let selector = selected_vector_selector(&cfg.config).map(ToString::to_string);
    let selected = collect_selected_vectors(cfg, selector.as_deref(), collections)?;
    let selected_elapsed = selector_started_at.elapsed();
    let snapshot_started_at = Instant::now();
    let snapshot = cfg.snapshot();
    let snapshot_elapsed = snapshot_started_at.elapsed();
    info!(
        "analyze response build sha256={} selector={:?} selected_counts=in:{} bl:{} fn:{} selected_elapsed_ms={} snapshot_elapsed_ms={} total_elapsed_ms={}",
        digest_hex(data),
        selector,
        selected.instructions.len(),
        selected.blocks.len(),
        selected.functions.len(),
        selected_elapsed.as_millis(),
        snapshot_elapsed.as_millis(),
        total_started_at.elapsed().as_millis(),
    );
    Ok(AnalyzeResponse {
        snapshot,
        selector,
        selected,
    })
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
            collections: Vec::new(),
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
    collections: BTreeSet<Collection>,
) -> Result<AnalyzeResponse, ServerError> {
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
    finalize_graph(&mut cfg, &data, &attributes, &corpora, &collections)
}

fn analyze_elf(
    config: &mut Config,
    requested_architecture: Option<Architecture>,
    data: Vec<u8>,
    magic: Magic,
    corpora: Vec<String>,
    collections: BTreeSet<Collection>,
) -> Result<AnalyzeResponse, ServerError> {
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
    finalize_graph(&mut cfg, &data, &attributes, &corpora, &collections)
}

fn analyze_macho(
    config: &mut Config,
    requested_architecture: Option<Architecture>,
    data: Vec<u8>,
    magic: Magic,
    corpora: Vec<String>,
    collections: BTreeSet<Collection>,
) -> Result<AnalyzeResponse, ServerError> {
    let macho = MACHO::from_bytes(data.clone(), config.clone()).map_err(|error| {
        ServerError::processor(format!("failed to parse macho image: {}", error))
    })?;

    let slices: Vec<_> = macho.slices().collect();
    let available_architectures: Vec<Architecture> = slices
        .iter()
        .map(|slice| slice.architecture())
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
        let detected_architecture = slice.architecture();
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
        let executable_ranges = slice.executable_virtual_address_ranges();
        let entrypoints = slice
            .entrypoint_virtual_addresses()
            .into_iter()
            .filter(|address| {
                executable_ranges
                    .iter()
                    .any(|(start, end)| *address >= *start && *address < *end)
            })
            .collect();
        let mut cfg = Graph::new(architecture, config.clone());
        let disassembler =
            Disassembler::new(architecture, image, executable_ranges, config.clone())
                .map_err(|error| ServerError::processor(error.to_string()))?;
        disassembler
            .disassemble(entrypoints, &mut cfg)
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
    finalize_graph(&mut graph, &data, &attributes, &corpora, &collections)
}

fn analyze_code(
    config: &mut Config,
    requested_architecture: Option<Architecture>,
    data: Vec<u8>,
    magic: Magic,
    corpora: Vec<String>,
    collections: BTreeSet<Collection>,
) -> Result<AnalyzeResponse, ServerError> {
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
        Architecture::ARM64 | Architecture::AMD64 | Architecture::I386 => {
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
    finalize_graph(&mut cfg, &data, &attributes, &corpora, &collections)
}
