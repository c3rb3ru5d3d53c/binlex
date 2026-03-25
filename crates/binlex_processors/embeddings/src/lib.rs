use burn::tensor::{Tensor, TensorData};
use burn::{Dispatch, DispatchDevice};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::hash::{Hash, Hasher};
use std::sync::OnceLock;
use twox_hash::XxHash64;

use binlex::config::{
    ConfigProcessor, ConfigProcessorTarget, ConfigProcessorTransport, ConfigProcessorTransports,
};
use binlex::controlflow::{Block, BlockJson, Function, FunctionJson, Instruction, InstructionJson};
use binlex::core::Architecture;
use binlex::core::{OperatingSystem, Transport};
use binlex::genetics::ChromosomeJson;
use binlex::math::stats::{max_or_zero, normalize_l2, weighted_histogram, weighted_mean};
use binlex::processor::{
    GraphProcessor, JsonProcessor, ProcessorContext, external_processor_registration,
};
use binlex::runtime::{Processor, ProcessorError};

const DEFAULT_DIMENSIONS: usize = 64;
const NIBBLE_BUCKETS: usize = 16;
const TRANSITION_BUCKETS: usize = 16;
const DEGREE_BUCKETS: usize = 8;
const SIZE_BUCKETS: usize = 8;
const INSTRUCTION_BUCKETS: usize = 8;
const CALL_BUCKETS: usize = 8;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EmbeddingsRequest {
    pub data: String,
    #[serde(default)]
    pub dimensions: Option<usize>,
    #[serde(default)]
    pub device: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EmbeddingsResponse {
    pub vector: Vec<f32>,
}

#[derive(Default)]
pub struct EmbeddingsProcessor;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct EmbeddingModelConfig {
    dimensions: usize,
    device: EmbeddingDevice,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
enum EmbeddingDevice {
    Cpu,
    Gpu,
    Cuda,
    Vulkan,
    Metal,
    WebGpu,
    Rocm,
}

static AUTO_GPU_DEVICE: OnceLock<EmbeddingDevice> = OnceLock::new();

#[derive(Default)]
struct FeatureFamilies {
    chromosome: Vec<f32>,
    scalar: Vec<f32>,
    cfg: Vec<f32>,
}

#[derive(Serialize, Deserialize, Clone)]
struct FunctionCfgBlock {
    address: u64,
    chromosome: ChromosomeJson,
    #[serde(default)]
    entropy: Option<f64>,
    size: usize,
    edges: usize,
    number_of_instructions: usize,
    call_count: usize,
    direct_call_count: usize,
    indirect_call_count: usize,
    conditional: bool,
    is_return: bool,
    is_trap: bool,
    contiguous: bool,
    #[serde(default)]
    next: Option<u64>,
    #[serde(default)]
    to: Vec<u64>,
    #[serde(default)]
    blocks: Vec<u64>,
}

fn parse_device(value: Option<&str>) -> EmbeddingDevice {
    match value.unwrap_or("cpu").trim().to_ascii_lowercase().as_str() {
        "cuda" => EmbeddingDevice::Cuda,
        "vulkan" => EmbeddingDevice::Vulkan,
        "metal" => EmbeddingDevice::Metal,
        "webgpu" => EmbeddingDevice::WebGpu,
        "rocm" => EmbeddingDevice::Rocm,
        "gpu" => EmbeddingDevice::Gpu,
        _ => EmbeddingDevice::Cpu,
    }
}

fn gpu_probe_candidates() -> &'static [EmbeddingDevice] {
    #[cfg(target_os = "macos")]
    {
        &[EmbeddingDevice::Metal]
    }
    #[cfg(not(target_os = "macos"))]
    {
        &[EmbeddingDevice::Cuda, EmbeddingDevice::Vulkan]
    }
}

fn chromosome_histogram(vector: &[u8]) -> Vec<f32> {
    let mut histogram = vec![0.0f32; NIBBLE_BUCKETS];
    if vector.is_empty() {
        return histogram;
    }

    for nibble in vector {
        let bucket = (*nibble as usize) % NIBBLE_BUCKETS;
        histogram[bucket] += 1.0;
    }

    let total = vector.len() as f32;
    for value in &mut histogram {
        *value /= total;
    }
    histogram
}

fn chromosome_transitions(vector: &[u8]) -> Vec<f32> {
    let mut histogram = vec![0.0f32; TRANSITION_BUCKETS];
    if vector.len() < 2 {
        return histogram;
    }

    for window in vector.windows(2) {
        let transition = ((window[0] << 4) | window[1]) as usize;
        histogram[transition % TRANSITION_BUCKETS] += 1.0;
    }

    let total = (vector.len() - 1) as f32;
    for value in &mut histogram {
        *value /= total;
    }
    histogram
}

fn chromosome_feature_vector(chromosome: Option<&ChromosomeJson>) -> Vec<f32> {
    let mut features = Vec::with_capacity(NIBBLE_BUCKETS + TRANSITION_BUCKETS + 4);
    if let Some(chromosome) = chromosome {
        features.extend(chromosome_histogram(&chromosome.vector));
        features.extend(chromosome_transitions(&chromosome.vector));
        features.push((chromosome.vector.len() as f32 / 512.0).clamp(0.0, 1.0));
        features.push((chromosome.pattern.len() as f32 / 1024.0).clamp(0.0, 1.0));
        features.push((chromosome.entropy.unwrap_or_default() as f32 / 8.0).clamp(0.0, 1.0));
        features.push(1.0);
    } else {
        features.extend(std::iter::repeat_n(
            0.0,
            NIBBLE_BUCKETS + TRANSITION_BUCKETS + 4,
        ));
    }
    features
}

fn push_scaled(features: &mut Vec<f32>, value: f32, scale: f32) {
    let scale = if scale <= 0.0 { 1.0 } else { scale };
    features.push((value / scale).clamp(0.0, 1.0));
}

fn push_bool(features: &mut Vec<f32>, flag: bool) {
    features.push(if flag { 1.0 } else { 0.0 });
}

fn instruction_features(instruction: &InstructionJson) -> FeatureFamilies {
    let mut scalar = Vec::with_capacity(16);
    push_scaled(&mut scalar, instruction.edges as f32, 8.0);
    push_scaled(&mut scalar, instruction.size as f32, 16.0);
    push_scaled(&mut scalar, instruction.functions.len() as f32, 8.0);
    push_scaled(&mut scalar, instruction.blocks.len() as f32, 8.0);
    push_scaled(&mut scalar, instruction.to.len() as f32, 8.0);
    push_bool(&mut scalar, instruction.is_call);
    push_bool(&mut scalar, instruction.is_return);
    push_bool(&mut scalar, instruction.is_jump);
    push_bool(&mut scalar, instruction.is_trap);
    push_bool(&mut scalar, instruction.is_conditional);
    push_bool(&mut scalar, instruction.is_prologue);
    push_bool(&mut scalar, instruction.is_block_start);
    push_bool(&mut scalar, instruction.is_function_start);
    push_bool(&mut scalar, instruction.has_indirect_target);
    push_bool(&mut scalar, instruction.next.is_some());
    FeatureFamilies {
        chromosome: chromosome_feature_vector(Some(&instruction.chromosome)),
        scalar,
        cfg: Vec::new(),
    }
}

fn block_features(block: &BlockJson) -> FeatureFamilies {
    let mut scalar = Vec::with_capacity(12);
    push_scaled(&mut scalar, block.entropy.unwrap_or_default() as f32, 8.0);
    push_scaled(&mut scalar, block.edges as f32, 16.0);
    push_scaled(&mut scalar, block.size as f32, 4096.0);
    push_scaled(&mut scalar, block.number_of_instructions as f32, 256.0);
    push_scaled(&mut scalar, block.functions.len() as f32, 32.0);
    push_scaled(&mut scalar, block.blocks.len() as f32, 32.0);
    push_scaled(&mut scalar, block.instructions.len() as f32, 256.0);
    push_scaled(&mut scalar, block.to.len() as f32, 16.0);
    push_bool(&mut scalar, block.conditional);
    push_bool(&mut scalar, block.contiguous);
    push_bool(&mut scalar, block.next.is_some());
    FeatureFamilies {
        chromosome: chromosome_feature_vector(Some(&block.chromosome)),
        scalar,
        cfg: Vec::new(),
    }
}

fn function_features(function: &FunctionJson) -> FeatureFamilies {
    let mut scalar = Vec::with_capacity(13);
    push_scaled(
        &mut scalar,
        function.entropy.unwrap_or_default() as f32,
        8.0,
    );
    push_scaled(&mut scalar, function.edges as f32, 256.0);
    push_scaled(&mut scalar, function.size as f32, 65536.0);
    push_scaled(&mut scalar, function.number_of_instructions as f32, 4096.0);
    push_scaled(&mut scalar, function.number_of_blocks as f32, 512.0);
    push_scaled(&mut scalar, function.cyclomatic_complexity as f32, 256.0);
    push_scaled(
        &mut scalar,
        function.average_instructions_per_block as f32,
        128.0,
    );
    push_scaled(&mut scalar, function.functions.len() as f32, 64.0);
    push_scaled(&mut scalar, function.blocks.len() as f32, 512.0);
    push_bool(&mut scalar, function.contiguous);
    push_bool(&mut scalar, function.bytes.is_some());
    push_bool(&mut scalar, function.chromosome.is_some());
    FeatureFamilies {
        chromosome: chromosome_feature_vector(function.chromosome.as_ref()),
        scalar,
        cfg: Vec::new(),
    }
}

fn function_cfg_features(value: &Value) -> Vec<f32> {
    let mut features = Vec::new();
    let Some(cfg_blocks_value) = value.get("cfg_blocks") else {
        features.extend(std::iter::repeat_n(
            0.0,
            NIBBLE_BUCKETS
                + TRANSITION_BUCKETS
                + DEGREE_BUCKETS * 2
                + SIZE_BUCKETS
                + INSTRUCTION_BUCKETS
                + CALL_BUCKETS
                + CALL_BUCKETS * 2
                + 19,
        ));
        return features;
    };

    let Ok(cfg_blocks) = serde_json::from_value::<Vec<FunctionCfgBlock>>(cfg_blocks_value.clone())
    else {
        features.extend(std::iter::repeat_n(
            0.0,
            NIBBLE_BUCKETS
                + TRANSITION_BUCKETS
                + DEGREE_BUCKETS * 2
                + SIZE_BUCKETS
                + INSTRUCTION_BUCKETS
                + CALL_BUCKETS
                + CALL_BUCKETS * 2
                + 19,
        ));
        return features;
    };

    if cfg_blocks.is_empty() {
        features.extend(std::iter::repeat_n(
            0.0,
            NIBBLE_BUCKETS
                + TRANSITION_BUCKETS
                + DEGREE_BUCKETS * 2
                + SIZE_BUCKETS
                + INSTRUCTION_BUCKETS
                + CALL_BUCKETS
                + CALL_BUCKETS * 2
                + 19,
        ));
        return features;
    }

    let mut nibble = vec![0.0f32; NIBBLE_BUCKETS];
    let mut transitions = vec![0.0f32; TRANSITION_BUCKETS];
    let mut indegree = BTreeMap::<u64, usize>::new();
    let mut block_index = BTreeSet::<u64>::new();
    let mut outdegrees = Vec::with_capacity(cfg_blocks.len());
    let mut instruction_counts = Vec::with_capacity(cfg_blocks.len());
    let mut block_sizes = Vec::with_capacity(cfg_blocks.len());
    let mut entropies = Vec::with_capacity(cfg_blocks.len());
    let mut edge_counts = Vec::with_capacity(cfg_blocks.len());
    let mut call_counts = Vec::with_capacity(cfg_blocks.len());
    let mut call_densities = Vec::with_capacity(cfg_blocks.len());
    let mut direct_call_counts = Vec::with_capacity(cfg_blocks.len());
    let mut indirect_call_counts = Vec::with_capacity(cfg_blocks.len());
    let mut direct_call_densities = Vec::with_capacity(cfg_blocks.len());
    let mut indirect_call_densities = Vec::with_capacity(cfg_blocks.len());
    let mut base_weights = Vec::with_capacity(cfg_blocks.len());
    let mut conditional = 0usize;
    let mut exits = 0usize;
    let mut fallthroughs = 0usize;
    let mut backedges = 0usize;
    let mut call_blocks = 0usize;
    let mut indirect_call_blocks = 0usize;
    let mut return_exits = 0usize;
    let mut trap_exits = 0usize;
    let mut self_loops = 0usize;
    let mut loop_headers = 0usize;

    for block in &cfg_blocks {
        block_index.insert(block.address);
        for (bucket, value) in chromosome_histogram(&block.chromosome.vector)
            .into_iter()
            .enumerate()
        {
            nibble[bucket] += value;
        }
        for (bucket, value) in chromosome_transitions(&block.chromosome.vector)
            .into_iter()
            .enumerate()
        {
            transitions[bucket] += value;
        }

        let successors = block.blocks.len() as f32;
        outdegrees.push(successors);
        instruction_counts.push(block.number_of_instructions as f32);
        block_sizes.push(block.size as f32);
        entropies.push(block.entropy.unwrap_or_default() as f32);
        edge_counts.push(block.edges as f32);
        call_counts.push(block.call_count as f32);
        direct_call_counts.push(block.direct_call_count as f32);
        indirect_call_counts.push(block.indirect_call_count as f32);
        let call_density = if block.number_of_instructions == 0 {
            0.0
        } else {
            block.call_count as f32 / block.number_of_instructions as f32
        };
        let direct_call_density = if block.number_of_instructions == 0 {
            0.0
        } else {
            block.direct_call_count as f32 / block.number_of_instructions as f32
        };
        let indirect_call_density = if block.number_of_instructions == 0 {
            0.0
        } else {
            block.indirect_call_count as f32 / block.number_of_instructions as f32
        };
        call_densities.push(call_density);
        direct_call_densities.push(direct_call_density);
        indirect_call_densities.push(indirect_call_density);
        if block.call_count > 0 {
            call_blocks += 1;
        }
        if block.indirect_call_count > 0 {
            indirect_call_blocks += 1;
        }
        let mut weight = 1.0f32;
        weight += (block.number_of_instructions as f32 / 8.0).min(2.0);
        weight += (block.edges as f32 / 4.0).min(2.0);
        if block.conditional {
            weight += 0.5;
        }
        if block.call_count > 0 {
            weight += 0.5;
        }
        if block.indirect_call_count > 0 {
            weight += 0.5;
        }
        if block.next.is_some() {
            weight += 0.25;
        }
        base_weights.push(weight);
        if block.conditional {
            conditional += 1;
        }
        if block.next.is_some() {
            fallthroughs += 1;
        }
        if block.blocks.is_empty() {
            exits += 1;
        }
        if block.is_return {
            return_exits += 1;
        }
        if block.is_trap {
            trap_exits += 1;
        }
        for successor in &block.blocks {
            *indegree.entry(*successor).or_default() += 1;
            if *successor <= block.address {
                backedges += 1;
                if *successor == block.address {
                    self_loops += 1;
                }
            }
        }
    }

    let block_count = cfg_blocks.len() as f32;
    for value in &mut nibble {
        *value /= block_count;
    }
    for value in &mut transitions {
        *value /= block_count;
    }
    features.extend(nibble);
    features.extend(transitions);

    let mut indegrees = Vec::with_capacity(cfg_blocks.len());
    let mut interior_edges = 0usize;
    let mut weights = Vec::with_capacity(cfg_blocks.len());
    for block in &cfg_blocks {
        let indegree_value = *indegree.get(&block.address).unwrap_or(&0) as f32;
        indegrees.push(indegree_value);
        let receives_backedge = block.blocks.iter().any(|target| *target <= block.address)
            || cfg_blocks.iter().any(|candidate| {
                candidate
                    .blocks
                    .iter()
                    .any(|target| *target == block.address && candidate.address >= block.address)
            });
        if receives_backedge && !block.blocks.is_empty() {
            loop_headers += 1;
        }
        let mut weight = base_weights[weights.len()];
        weight += (indegree_value / 4.0).min(2.0);
        if block.address == cfg_blocks[0].address {
            weight += 0.75;
        }
        if block.blocks.is_empty() {
            weight += 0.5;
        }
        weights.push(weight);
        interior_edges += block
            .blocks
            .iter()
            .filter(|target| block_index.contains(target))
            .count();
    }

    let weight_sum = weights.iter().sum::<f32>().max(1.0);
    for (block, weight) in cfg_blocks.iter().zip(weights.iter()) {
        let normalized_weight = *weight / weight_sum;
        let block_histogram = chromosome_histogram(&block.chromosome.vector);
        let block_transitions = chromosome_transitions(&block.chromosome.vector);
        for (bucket, value) in block_histogram.into_iter().enumerate() {
            features[bucket] += value * normalized_weight;
        }
        for (bucket, value) in block_transitions.into_iter().enumerate() {
            features[NIBBLE_BUCKETS + bucket] += value * normalized_weight;
        }
    }

    features.extend(weighted_histogram(
        &outdegrees,
        &weights,
        DEGREE_BUCKETS,
        1.0,
    ));
    features.extend(weighted_histogram(
        &indegrees,
        &weights,
        DEGREE_BUCKETS,
        1.0,
    ));
    features.extend(weighted_histogram(
        &block_sizes,
        &weights,
        SIZE_BUCKETS,
        32.0,
    ));
    features.extend(weighted_histogram(
        &instruction_counts,
        &weights,
        INSTRUCTION_BUCKETS,
        2.0,
    ));
    features.extend(weighted_histogram(
        &call_counts,
        &weights,
        CALL_BUCKETS,
        1.0,
    ));
    features.extend(weighted_histogram(
        &direct_call_counts,
        &weights,
        CALL_BUCKETS,
        1.0,
    ));
    features.extend(weighted_histogram(
        &indirect_call_counts,
        &weights,
        CALL_BUCKETS,
        1.0,
    ));

    let entry_block = &cfg_blocks[0];
    let entry_outdegree = entry_block.blocks.len() as f32;
    let entry_indegree = *indegree.get(&entry_block.address).unwrap_or(&0) as f32;
    let entry_call_density = if entry_block.number_of_instructions == 0 {
        0.0
    } else {
        entry_block.call_count as f32 / entry_block.number_of_instructions as f32
    };
    let entry_indirect_call_density = if entry_block.number_of_instructions == 0 {
        0.0
    } else {
        entry_block.indirect_call_count as f32 / entry_block.number_of_instructions as f32
    };

    push_scaled(&mut features, interior_edges as f32, 2048.0);
    push_scaled(&mut features, weighted_mean(&outdegrees, &weights), 8.0);
    push_scaled(&mut features, max_or_zero(&outdegrees), 8.0);
    push_scaled(&mut features, weighted_mean(&indegrees, &weights), 8.0);
    push_scaled(&mut features, max_or_zero(&indegrees), 8.0);
    push_scaled(
        &mut features,
        weighted_mean(&instruction_counts, &weights),
        128.0,
    );
    push_scaled(&mut features, weighted_mean(&entropies, &weights), 8.0);
    push_scaled(&mut features, weighted_mean(&edge_counts, &weights), 16.0);
    push_scaled(&mut features, weighted_mean(&call_counts, &weights), 8.0);
    push_scaled(&mut features, weighted_mean(&call_densities, &weights), 1.0);
    push_scaled(
        &mut features,
        weighted_mean(&direct_call_counts, &weights),
        8.0,
    );
    push_scaled(
        &mut features,
        weighted_mean(&indirect_call_counts, &weights),
        8.0,
    );
    push_scaled(
        &mut features,
        weighted_mean(&direct_call_densities, &weights),
        1.0,
    );
    push_scaled(
        &mut features,
        weighted_mean(&indirect_call_densities, &weights),
        1.0,
    );
    push_scaled(&mut features, entry_outdegree, 8.0);
    push_scaled(&mut features, entry_indegree, 8.0);
    push_scaled(
        &mut features,
        entry_block.number_of_instructions as f32,
        128.0,
    );
    push_scaled(&mut features, entry_block.size as f32, 512.0);
    push_scaled(
        &mut features,
        entry_block.entropy.unwrap_or_default() as f32,
        8.0,
    );
    push_scaled(&mut features, entry_call_density, 1.0);
    push_scaled(&mut features, entry_indirect_call_density, 1.0);
    push_bool(&mut features, entry_block.conditional);
    push_bool(&mut features, entry_block.is_return);
    push_bool(&mut features, entry_block.is_trap);
    push_scaled(&mut features, conditional as f32 / block_count, 1.0);
    push_scaled(&mut features, call_blocks as f32 / block_count, 1.0);
    push_scaled(
        &mut features,
        indirect_call_blocks as f32 / block_count,
        1.0,
    );
    push_scaled(&mut features, exits as f32 / block_count, 1.0);
    push_scaled(&mut features, return_exits as f32 / block_count, 1.0);
    push_scaled(&mut features, trap_exits as f32 / block_count, 1.0);
    push_scaled(&mut features, fallthroughs as f32 / block_count, 1.0);
    push_scaled(&mut features, backedges as f32, 256.0);
    push_scaled(&mut features, backedges as f32 / block_count, 8.0);
    push_scaled(&mut features, self_loops as f32 / block_count, 8.0);
    push_scaled(&mut features, loop_headers as f32 / block_count, 1.0);
    features
}

fn extract_features(value: &Value) -> FeatureFamilies {
    match value.get("type").and_then(Value::as_str) {
        Some("instruction") => serde_json::from_value::<InstructionJson>(value.clone())
            .map(|instruction| instruction_features(&instruction))
            .unwrap_or_default(),
        Some("block") => serde_json::from_value::<BlockJson>(value.clone())
            .map(|block| block_features(&block))
            .unwrap_or_default(),
        Some("function") => serde_json::from_value::<FunctionJson>(value.clone())
            .map(|function| {
                let mut features = function_features(&function);
                features.cfg = function_cfg_features(value);
                features
            })
            .unwrap_or_default(),
        _ => FeatureFamilies {
            scalar: vec![0.0],
            ..Default::default()
        },
    }
}

fn burn_project(
    features: &[f32],
    dimensions: usize,
    seed: u64,
    device_preference: EmbeddingDevice,
) -> Vec<f32> {
    if device_preference != EmbeddingDevice::Cpu {
        if let Some(projected) = try_burn_project(features, dimensions, seed, device_preference) {
            return projected;
        }
    }
    try_burn_project(features, dimensions, seed, EmbeddingDevice::Cpu)
        .unwrap_or_else(|| vec![0.0; dimensions])
}

fn try_burn_project(
    features: &[f32],
    dimensions: usize,
    seed: u64,
    device_preference: EmbeddingDevice,
) -> Option<Vec<f32>> {
    std::panic::catch_unwind(|| {
        let device = resolve_burn_device(device_preference);
        let mut values = vec![0.0f32; dimensions];
        if features.is_empty() {
            return values;
        }

        for (index, feature) in features.iter().enumerate() {
            let mut hasher = XxHash64::with_seed(seed.wrapping_add(index as u64));
            index.hash(&mut hasher);
            feature.to_bits().hash(&mut hasher);
            let bucket = (hasher.finish() as usize) % dimensions;
            values[bucket] += *feature;
        }

        let tensor =
            Tensor::<Dispatch, 1>::from_data(TensorData::new(values, [dimensions]), &device);
        let data = tensor.into_data();
        data.to_vec::<f32>()
            .unwrap_or_else(|_| vec![0.0; dimensions])
    })
    .ok()
}

fn resolve_burn_device(device_preference: EmbeddingDevice) -> DispatchDevice {
    match device_preference {
        EmbeddingDevice::Cpu => DispatchDevice::NdArray(Default::default()),
        EmbeddingDevice::Cuda => DispatchDevice::Cuda(Default::default()),
        EmbeddingDevice::Vulkan => DispatchDevice::Vulkan(Default::default()),
        EmbeddingDevice::Gpu => resolve_burn_device(detect_gpu_device()),
        // These config values are accepted, but this build is currently wired to
        // CUDA/Vulkan for real GPU execution. Unsupported selections fall back to CPU.
        EmbeddingDevice::Metal | EmbeddingDevice::WebGpu | EmbeddingDevice::Rocm => {
            DispatchDevice::NdArray(Default::default())
        }
    }
}

fn detect_gpu_device() -> EmbeddingDevice {
    *AUTO_GPU_DEVICE.get_or_init(|| {
        for candidate in gpu_probe_candidates() {
            if probe_dispatch_device(*candidate) {
                return *candidate;
            }
        }
        EmbeddingDevice::Cpu
    })
}

fn probe_dispatch_device(device: EmbeddingDevice) -> bool {
    std::panic::catch_unwind(|| {
        let dispatch = resolve_burn_device(device);
        let tensor =
            Tensor::<Dispatch, 1>::from_data(TensorData::new(vec![1.0f32], [1]), &dispatch);
        let _ = tensor.into_data().to_vec::<f32>().ok();
    })
    .is_ok()
}

fn smooth_vector(values: &mut [f32]) {
    if values.len() < 3 {
        return;
    }
    let original = values.to_vec();
    for index in 0..values.len() {
        let previous = original[(index + original.len() - 1) % original.len()];
        let current = original[index];
        let next = original[(index + 1) % original.len()];
        values[index] = current * 0.7 + (previous + next) * 0.15;
    }
}

fn embed(value: &Value, config: &EmbeddingModelConfig) -> Vec<f32> {
    let dimensions = config.dimensions.max(1);
    let families = extract_features(value);
    let chromosome = burn_project(&families.chromosome, dimensions, 0xC0DEC0DE, config.device);
    let scalar = burn_project(&families.scalar, dimensions, 0x51CA1A5E, config.device);
    let cfg = burn_project(&families.cfg, dimensions, 0xCF6CF6CF, config.device);

    let mut chromosome_weight = if families.chromosome.is_empty() {
        0.0
    } else {
        0.45
    };
    let mut scalar_weight = if families.scalar.is_empty() {
        0.0
    } else {
        0.30
    };
    let mut cfg_weight = if families.cfg.is_empty() { 0.0 } else { 0.25 };
    let total_weight = chromosome_weight + scalar_weight + cfg_weight;
    if total_weight == 0.0 {
        return vec![0.0; dimensions];
    }
    chromosome_weight /= total_weight;
    scalar_weight /= total_weight;
    cfg_weight /= total_weight;

    let mut vector = vec![0.0f32; dimensions];
    for index in 0..dimensions {
        vector[index] = chromosome[index] * chromosome_weight
            + scalar[index] * scalar_weight
            + cfg[index] * cfg_weight;
    }
    smooth_vector(&mut vector);
    normalize_l2(&mut vector);
    vector
}

fn processor_config(config: &binlex::Config) -> Option<&ConfigProcessor> {
    config.processors.processor(EmbeddingsProcessor::NAME)
}

fn configured_dimensions(config: &binlex::Config) -> usize {
    processor_config(config)
        .and_then(|processor| processor.option_integer("dimensions"))
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_DIMENSIONS)
}

fn configured_dimensions_from_context<C: ProcessorContext>(context: &C) -> usize {
    context
        .processor(EmbeddingsProcessor::NAME)
        .and_then(|processor| processor.option_integer("dimensions"))
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_DIMENSIONS)
}

fn configured_device(config: &binlex::Config) -> EmbeddingDevice {
    parse_device(processor_config(config).and_then(|processor| processor.option_string("device")))
}

fn configured_device_from_context<C: ProcessorContext>(context: &C) -> String {
    context
        .processor(EmbeddingsProcessor::NAME)
        .and_then(|processor| processor.option_string("device"))
        .unwrap_or("cpu")
        .to_string()
}

fn local_output(data: Value, config: &binlex::Config) -> Value {
    let dimensions = configured_dimensions(config);
    let vector = embed(
        &data,
        &EmbeddingModelConfig {
            dimensions,
            device: configured_device(config),
        },
    );
    json!({
        "vector": vector,
    })
}

fn process_value(data: Value, config: &binlex::Config) -> Option<Value> {
    Some(local_output(data, config))
}

impl Processor for EmbeddingsProcessor {
    const NAME: &'static str = "embeddings";
    type Request = EmbeddingsRequest;
    type Response = EmbeddingsResponse;

    fn request(&self, request: Self::Request) -> Result<Self::Response, ProcessorError> {
        let data: Value = serde_json::from_str(&request.data)
            .map_err(|error| ProcessorError::Serialization(error.to_string()))?;
        let config = EmbeddingModelConfig {
            dimensions: request.dimensions.unwrap_or(DEFAULT_DIMENSIONS),
            device: parse_device(request.device.as_deref()),
        };
        let vector = embed(&data, &config);
        Ok(EmbeddingsResponse { vector })
    }
}

impl JsonProcessor for EmbeddingsProcessor {
    fn request<C: ProcessorContext>(
        context: &C,
        data: Value,
    ) -> Result<Self::Request, ProcessorError> {
        Ok(EmbeddingsRequest {
            data: serde_json::to_string(&data)
                .map_err(|error| ProcessorError::Serialization(error.to_string()))?,
            dimensions: Some(configured_dimensions_from_context(context)),
            device: Some(configured_device_from_context(context)),
        })
    }

    fn response(response: Self::Response) -> Result<Value, ProcessorError> {
        Ok(json!({
            "vector": response.vector,
        }))
    }
}

impl GraphProcessor for EmbeddingsProcessor {
    fn function_json(function: &Function<'_>) -> Option<Value> {
        function_embedding_input(function).ok()
    }

    fn instruction(instruction: &Instruction) -> Option<Value> {
        let data = serde_json::to_value(instruction.process_base()).ok()?;
        process_value(data, &instruction.config)
    }

    fn block(block: &Block<'_>) -> Option<Value> {
        let data = serde_json::to_value(block.process_base()).ok()?;
        process_value(data, &block.cfg.config)
    }

    fn function(function: &Function<'_>) -> Option<Value> {
        let data = function_embedding_input(function).ok()?;
        process_value(data, &function.cfg.config)
    }
}

fn function_embedding_input(function: &Function<'_>) -> Result<Value, serde_json::Error> {
    let mut data = serde_json::to_value(function.process_base())?;
    let cfg_blocks = function
        .blocks()
        .into_iter()
        .map(|block| {
            let instructions = block.instructions();
            let call_count = instructions
                .iter()
                .filter(|instruction| instruction.is_call)
                .count();
            let direct_call_count = instructions
                .iter()
                .filter(|instruction| instruction.is_call && !instruction.has_indirect_target)
                .count();
            let indirect_call_count = instructions
                .iter()
                .filter(|instruction| instruction.is_call && instruction.has_indirect_target)
                .count();
            FunctionCfgBlock {
                call_count,
                direct_call_count,
                indirect_call_count,
                address: block.address(),
                chromosome: block.chromosome_json(),
                entropy: block.entropy(),
                size: block.size(),
                edges: block.edges(),
                number_of_instructions: block.number_of_instructions(),
                conditional: block.terminator.is_conditional,
                is_return: block.terminator.is_return,
                is_trap: block.terminator.is_trap,
                contiguous: block.contiguous(),
                next: block.next(),
                to: block.to().into_iter().collect(),
                blocks: block.blocks().into_iter().collect(),
            }
        })
        .collect::<Vec<_>>();

    if let Value::Object(ref mut map) = data {
        map.insert("cfg_blocks".to_string(), serde_json::to_value(cfg_blocks)?);
    }
    Ok(data)
}

pub fn registration() -> binlex::processor::ProcessorRegistration {
    external_processor_registration(
        EmbeddingsProcessor::NAME,
        ">=2.0.0 <2.1.0",
        &[
            OperatingSystem::WINDOWS,
            OperatingSystem::LINUX,
            OperatingSystem::MACOS,
        ],
        &[Architecture::AMD64, Architecture::I386, Architecture::CIL],
        &[Transport::IPC, Transport::HTTP],
        ConfigProcessor {
            enabled: true,
            instructions: ConfigProcessorTarget {
                enabled: false,
                options: BTreeMap::new(),
            },
            blocks: ConfigProcessorTarget {
                enabled: true,
                options: BTreeMap::new(),
            },
            functions: ConfigProcessorTarget {
                enabled: true,
                options: BTreeMap::new(),
            },
            options: BTreeMap::from([
                ("dimensions".to_string(), 64.into()),
                ("device".to_string(), "cpu".into()),
            ]),
            transport: ConfigProcessorTransports {
                ipc: ConfigProcessorTransport {
                    enabled: true,
                    options: BTreeMap::new(),
                },
                http: ConfigProcessorTransport {
                    enabled: false,
                    options: BTreeMap::from([
                        ("url".to_string(), "http://127.0.0.1:5000".into()),
                        ("verify".to_string(), false.into()),
                    ]),
                },
            },
        },
    )
}
