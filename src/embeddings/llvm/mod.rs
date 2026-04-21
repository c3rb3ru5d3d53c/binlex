use crate::Config;
use crate::controlflow::{Block, Function, Instruction};
use crate::io::Stderr;
use crate::lifters::llvm::Lifter as LlvmLifter;
use crate::math::stats::normalize_l2;
use inkwell::context::Context;
use inkwell::memory_buffer::MemoryBuffer;
use inkwell::module::Module;
use inkwell::values::{BasicValue, CallSiteValue, FunctionValue, InstructionOpcode, Operand};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::io::Error;
use twox_hash::XxHash64;

pub mod block;
pub mod function;
pub mod instruction;

const HASH_BUCKETS: usize = 64;
const SEQUENCE_BUCKETS: usize = 96;
const DEGREE_BUCKETS: usize = 8;

#[derive(Clone, Debug)]
pub(crate) struct EmbeddingModelConfig {
    pub(crate) dimensions: usize,
    pub(crate) device: EmbeddingDevice,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EmbeddingDevice {
    Cpu,
    Gpu,
    Cuda,
    Vulkan,
    Metal,
    WebGpu,
    Rocm,
}

pub(crate) struct FeatureFamilies {
    pub(crate) semantic: Vec<f32>,
    pub(crate) control_flow: Vec<f32>,
    pub(crate) sequence: Vec<f32>,
    pub(crate) semantic_weight: f32,
    pub(crate) control_flow_weight: f32,
    pub(crate) sequence_weight: f32,
}

pub(crate) fn configured_model(config: &Config) -> EmbeddingModelConfig {
    EmbeddingModelConfig {
        dimensions: config.embeddings.llvm.dimensions.max(1),
        device: parse_device(Some(config.embeddings.llvm.device.as_str())),
    }
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

fn push_scaled(features: &mut Vec<f32>, value: f32, scale: f32) {
    let scale = if scale <= 0.0 { 1.0 } else { scale };
    features.push((value / scale).clamp(0.0, 1.0));
}

fn push_bool(features: &mut Vec<f32>, flag: bool) {
    features.push(if flag { 1.0 } else { 0.0 });
}

fn extend_weighted(features: &mut Vec<f32>, values: impl IntoIterator<Item = f32>, weight: f32) {
    features.extend(values.into_iter().map(|value| value * weight));
}

fn optimize_lifter(lifter: LlvmLifter) -> Result<LlvmLifter, Error> {
    lifter
        .optimizers()?
        .mem2reg()?
        .sroa()?
        .gvn()?
        .cfg()?
        .dce()?
        .into_lifter()
        .normalized()
}

pub(crate) fn canonical_instruction_bitcode(instruction: &Instruction) -> Result<Vec<u8>, Error> {
    let mut lifter = LlvmLifter::new(instruction.config.clone());
    lifter.lift_instruction(instruction)?;
    let optimized = optimize_lifter(lifter)?;
    Ok(optimized.bitcode())
}

pub(crate) fn canonical_block_bitcode(block: &Block<'_>) -> Result<Vec<u8>, Error> {
    let mut lifter = LlvmLifter::new(block.cfg.config.clone());
    lifter.lift_block(block)?;
    let optimized = optimize_lifter(lifter)?;
    Ok(optimized.bitcode())
}

pub(crate) fn canonical_function_bitcode(function: &Function<'_>) -> Result<Vec<u8>, Error> {
    let mut lifter = LlvmLifter::new(function.cfg.config.clone());
    lifter.lift_function(function)?;
    let optimized = optimize_lifter(lifter)?;
    Ok(optimized.bitcode())
}

pub(crate) fn parse_module_from_bitcode<'ctx>(
    context: &'ctx Context,
    bitcode: &[u8],
) -> Result<Module<'ctx>, Error> {
    let buffer = MemoryBuffer::create_from_memory_range_copy(bitcode, "binlex-embedding.bc");
    Module::parse_bitcode_from_buffer(&buffer, context)
        .map_err(|error| Error::other(error.to_string()))
}

pub(crate) fn primary_defined_function<'ctx>(module: &Module<'ctx>) -> Option<FunctionValue<'ctx>> {
    module
        .get_functions()
        .find(|function| function.get_first_basic_block().is_some())
}

fn opcode_token(opcode: InstructionOpcode) -> String {
    format!("{opcode:?}").to_ascii_lowercase()
}

fn helper_family(name: &str) -> String {
    if name == "binlex_instruction_address" {
        return "binlex_instruction_address".to_string();
    }
    for prefix in [
        "binlex_effect_cil_",
        "binlex_expr_cil_",
        "binlex_term_",
        "binlex_effect_",
        "binlex_expr_",
        "binlex_load_",
        "binlex_store_",
        "binlex_fence_",
        "binlex_trap_",
    ] {
        if name.starts_with(prefix) {
            return prefix.trim_end_matches('_').to_string();
        }
    }
    name.to_string()
}

fn hash_bucket<T: Hash>(value: &T, buckets: usize, seed: u64) -> usize {
    let mut hasher = XxHash64::with_seed(seed);
    value.hash(&mut hasher);
    (hasher.finish() as usize) % buckets.max(1)
}

fn hashed_feature_bag(values: &[String], buckets: usize, seed: u64) -> Vec<f32> {
    let mut result = vec![0.0f32; buckets.max(1)];
    if values.is_empty() {
        return result;
    }
    for value in values {
        let bucket = hash_bucket(value, result.len(), seed);
        result[bucket] += 1.0;
    }
    let total = values.len() as f32;
    for value in &mut result {
        *value /= total;
    }
    result
}

fn numeric_histogram(values: &[f32], buckets: usize, scale: f32) -> Vec<f32> {
    let mut result = vec![0.0f32; buckets.max(1)];
    if values.is_empty() {
        return result;
    }
    let scale = if scale <= 0.0 { 1.0 } else { scale };
    for value in values {
        let bucket = ((*value / scale) as usize).min(result.len() - 1);
        result[bucket] += 1.0;
    }
    let total = values.len() as f32;
    for value in &mut result {
        *value /= total;
    }
    result
}

fn build_ngrams(tokens: &[String], size: usize) -> Vec<String> {
    if tokens.len() < size || size == 0 {
        return Vec::new();
    }
    tokens
        .windows(size)
        .map(|window| window.join("->"))
        .collect::<Vec<_>>()
}

fn count_block_successors<'ctx>(function: FunctionValue<'ctx>) -> HashMap<String, usize> {
    let mut successors = HashMap::new();
    for block in function.get_basic_blocks() {
        let count = block
            .get_terminator()
            .map(|terminator| {
                terminator
                    .get_operands()
                    .filter(|operand| matches!(operand, Some(Operand::Block(_))))
                    .count()
            })
            .unwrap_or(0);
        successors.insert(block.get_name().to_string_lossy().into_owned(), count);
    }
    successors
}

pub(crate) fn semantic_features_from_module<'ctx>(
    function: FunctionValue<'ctx>,
) -> (Vec<f32>, Vec<String>, Vec<String>) {
    let mut opcodes = Vec::new();
    let mut helpers = Vec::new();
    let mut total_operands = 0f32;
    let mut constant_operands = 0f32;
    let mut block_operands = 0f32;
    let mut instruction_operands = 0f32;

    for block in function.get_basic_blocks() {
        let mut instruction = block.get_first_instruction();
        while let Some(current) = instruction {
            opcodes.push(opcode_token(current.get_opcode()));
            total_operands += current.get_num_operands() as f32;

            for operand in current.get_operands() {
                match operand {
                    Some(Operand::Block(_)) => block_operands += 1.0,
                    Some(Operand::Value(value)) => {
                        if value.is_const() {
                            constant_operands += 1.0;
                        }
                        if value.as_instruction_value().is_some() {
                            instruction_operands += 1.0;
                        }
                    }
                    None => {}
                }
            }

            if let Ok(callsite) = CallSiteValue::try_from(current) {
                if let Some(callee) = callsite.get_called_fn_value() {
                    let name = callee.get_name().to_string_lossy().into_owned();
                    if !name.is_empty() {
                        helpers.push(helper_family(&name));
                    }
                }
            }

            instruction = current.get_next_instruction();
        }
    }

    let instruction_count = opcodes.len().max(1) as f32;
    let opcode_features = hashed_feature_bag(&opcodes, HASH_BUCKETS, 0x51CA_A11A);
    let helper_features = hashed_feature_bag(&helpers, HASH_BUCKETS / 2, 0xB1B1_00E7);

    let opcode_matches = |names: &[&str]| -> f32 {
        opcodes
            .iter()
            .filter(|opcode| names.iter().any(|name| opcode.as_str() == *name))
            .count() as f32
    };

    let mut dataflow = Vec::new();
    for value in [
        opcode_matches(&["phi"]),
        opcode_matches(&["select"]),
        opcode_matches(&["load"]),
        opcode_matches(&["store"]),
        opcode_matches(&["getelementptr"]),
        opcode_matches(&["alloca"]),
        opcode_matches(&["trunc", "zext", "sext", "bitcast", "ptrtoint", "inttoptr"]),
        opcode_matches(&["add", "sub", "mul", "udiv", "sdiv", "urem", "srem"]),
        opcode_matches(&["and", "or", "xor", "shl", "lshr", "ashr"]),
        opcode_matches(&["icmp", "fcmp"]),
        opcode_matches(&["call"]),
        opcode_matches(&["br", "switch"]),
        opcode_matches(&["ret"]),
        opcode_matches(&["unreachable"]),
    ] {
        push_scaled(&mut dataflow, value, instruction_count);
    }

    let helper_count = helpers.len().max(1) as f32;
    let mut call_features = Vec::new();
    push_scaled(
        &mut call_features,
        opcode_matches(&["call"]),
        instruction_count,
    );
    push_scaled(
        &mut call_features,
        helpers
            .iter()
            .filter(|helper| helper.starts_with("binlex_term_"))
            .count() as f32,
        helper_count,
    );
    push_scaled(
        &mut call_features,
        helpers
            .iter()
            .filter(|helper| helper.starts_with("binlex_effect_"))
            .count() as f32,
        helper_count,
    );
    push_scaled(
        &mut call_features,
        helpers
            .iter()
            .filter(|helper| helper.starts_with("binlex_expr_"))
            .count() as f32,
        helper_count,
    );

    let mut memory_features = Vec::new();
    push_scaled(
        &mut memory_features,
        opcode_matches(&["load"]),
        instruction_count,
    );
    push_scaled(
        &mut memory_features,
        opcode_matches(&["store"]),
        instruction_count,
    );
    push_scaled(
        &mut memory_features,
        opcode_matches(&["getelementptr"]),
        instruction_count,
    );
    push_scaled(
        &mut memory_features,
        opcode_matches(&["alloca"]),
        instruction_count,
    );
    push_scaled(
        &mut memory_features,
        constant_operands,
        total_operands.max(1.0),
    );
    push_scaled(
        &mut memory_features,
        instruction_operands,
        total_operands.max(1.0),
    );
    push_scaled(
        &mut memory_features,
        block_operands,
        total_operands.max(1.0),
    );

    let mut effect_features = Vec::new();
    push_scaled(
        &mut effect_features,
        opcode_matches(&["br", "switch"]),
        instruction_count,
    );
    push_scaled(
        &mut effect_features,
        opcode_matches(&["ret"]),
        instruction_count,
    );
    push_scaled(
        &mut effect_features,
        opcode_matches(&["unreachable"]),
        instruction_count,
    );
    push_scaled(
        &mut effect_features,
        helpers
            .iter()
            .filter(|helper| helper.starts_with("binlex_trap_"))
            .count() as f32,
        helper_count,
    );
    push_scaled(
        &mut effect_features,
        helpers
            .iter()
            .filter(|helper| helper.starts_with("binlex_fence_"))
            .count() as f32,
        helper_count,
    );

    let mut features = Vec::new();
    extend_weighted(&mut features, opcode_features, 0.25);
    extend_weighted(&mut features, dataflow, 0.30);
    extend_weighted(&mut features, memory_features, 0.20);
    extend_weighted(&mut features, call_features, 0.15);
    extend_weighted(&mut features, effect_features, 0.10);
    extend_weighted(&mut features, helper_features, 0.10);

    (features, opcodes, helpers)
}

pub(crate) fn control_flow_features_for_function_module<'ctx>(
    function: FunctionValue<'ctx>,
) -> Vec<f32> {
    let blocks = function.get_basic_blocks();
    let block_count = blocks.len().max(1) as f32;
    let successor_counts = count_block_successors(function);
    let mut indegree = HashMap::<String, usize>::new();
    let mut outdegrees = Vec::with_capacity(blocks.len());
    let mut indegrees = Vec::with_capacity(blocks.len());
    let mut instruction_counts = Vec::with_capacity(blocks.len());
    let mut conditional_count = 0usize;
    let mut exit_count = 0usize;
    let mut return_count = 0usize;
    let mut unreachable_count = 0usize;
    let mut switch_count = 0usize;
    let mut invoke_count = 0usize;
    let mut backedge_count = 0usize;
    let mut loop_header_count = 0usize;

    let name_to_index = blocks
        .iter()
        .enumerate()
        .map(|(index, block)| (block.get_name().to_string_lossy().into_owned(), index))
        .collect::<HashMap<_, _>>();

    for block in &blocks {
        let name = block.get_name().to_string_lossy().into_owned();
        let outdegree = *successor_counts.get(&name).unwrap_or(&0);
        outdegrees.push(outdegree as f32);
        let instruction_count = block.get_instructions().into_iter().count().max(1);
        instruction_counts.push(instruction_count as f32);
        if let Some(terminator) = block.get_terminator() {
            match terminator.get_opcode() {
                InstructionOpcode::Br if outdegree > 1 => conditional_count += 1,
                InstructionOpcode::Switch => {
                    switch_count += 1;
                    if outdegree > 1 {
                        conditional_count += 1;
                    }
                }
                InstructionOpcode::Return => {
                    return_count += 1;
                    exit_count += 1;
                }
                InstructionOpcode::Unreachable => {
                    unreachable_count += 1;
                    exit_count += 1;
                }
                InstructionOpcode::Invoke => invoke_count += 1,
                _ => {
                    if outdegree == 0 {
                        exit_count += 1;
                    }
                }
            }

            for operand in terminator.get_operands() {
                if let Some(Operand::Block(target)) = operand {
                    let target_name = target.get_name().to_string_lossy().into_owned();
                    *indegree.entry(target_name.clone()).or_insert(0) += 1;
                    if let (Some(&source_index), Some(&target_index)) =
                        (name_to_index.get(&name), name_to_index.get(&target_name))
                    {
                        if target_index <= source_index {
                            backedge_count += 1;
                        }
                    }
                }
            }
        }
    }

    for block in &blocks {
        let name = block.get_name().to_string_lossy().into_owned();
        let value = *indegree.get(&name).unwrap_or(&0);
        indegrees.push(value as f32);
        if value >= 2 {
            loop_header_count += 1;
        }
    }

    let mut features = Vec::new();
    push_scaled(&mut features, blocks.len() as f32, 64.0);
    push_scaled(&mut features, conditional_count as f32, block_count);
    push_scaled(&mut features, exit_count as f32, block_count);
    push_scaled(&mut features, return_count as f32, block_count);
    push_scaled(&mut features, unreachable_count as f32, block_count);
    push_scaled(&mut features, switch_count as f32, block_count);
    push_scaled(&mut features, invoke_count as f32, block_count);
    push_scaled(&mut features, backedge_count as f32, block_count);
    push_scaled(&mut features, loop_header_count as f32, block_count);
    extend_weighted(
        &mut features,
        numeric_histogram(&outdegrees, DEGREE_BUCKETS, 8.0),
        0.35,
    );
    extend_weighted(
        &mut features,
        numeric_histogram(&indegrees, DEGREE_BUCKETS, 8.0),
        0.30,
    );
    extend_weighted(
        &mut features,
        numeric_histogram(&instruction_counts, DEGREE_BUCKETS, 32.0),
        0.20,
    );
    features
}

pub(crate) fn control_flow_features_for_block_module<'ctx>(
    function: FunctionValue<'ctx>,
) -> Vec<f32> {
    let mut instruction = function
        .get_first_basic_block()
        .and_then(|block| block.get_first_instruction());
    let mut instruction_count = 0usize;
    let mut terminator_opcode = InstructionOpcode::Return;
    let mut operand_blocks = 0usize;
    while let Some(current) = instruction {
        instruction_count += 1;
        if current.is_terminator() {
            terminator_opcode = current.get_opcode();
            operand_blocks = current
                .get_operands()
                .filter(|operand| matches!(operand, Some(Operand::Block(_))))
                .count();
        }
        instruction = current.get_next_instruction();
    }

    let mut features = Vec::new();
    push_scaled(&mut features, operand_blocks as f32, 16.0);
    push_scaled(&mut features, instruction_count as f32, 128.0);
    push_bool(
        &mut features,
        matches!(
            terminator_opcode,
            InstructionOpcode::Br | InstructionOpcode::Switch
        ),
    );
    push_bool(
        &mut features,
        terminator_opcode == InstructionOpcode::Return,
    );
    push_bool(
        &mut features,
        terminator_opcode == InstructionOpcode::Unreachable,
    );
    push_bool(
        &mut features,
        terminator_opcode == InstructionOpcode::Invoke,
    );
    features
}

pub(crate) fn sequence_features_from_tokens(opcodes: &[String], helpers: &[String]) -> Vec<f32> {
    let opcode_bigrams = build_ngrams(opcodes, 2);
    let opcode_trigrams = build_ngrams(opcodes, 3);
    let helper_bigrams = build_ngrams(helpers, 2);
    let mut features = Vec::new();
    extend_weighted(
        &mut features,
        hashed_feature_bag(&opcode_bigrams, SEQUENCE_BUCKETS, 0x0FC0_DE22),
        0.50,
    );
    extend_weighted(
        &mut features,
        hashed_feature_bag(&helper_bigrams, SEQUENCE_BUCKETS / 2, 0xA11E_E221),
        0.20,
    );
    extend_weighted(
        &mut features,
        hashed_feature_bag(&opcode_trigrams, SEQUENCE_BUCKETS, 0xCF61_A11C),
        0.30,
    );
    features
}

#[allow(dead_code)]
pub(crate) fn embed_families(families: FeatureFamilies, config: &EmbeddingModelConfig) -> Vec<f32> {
    embed_families_with_runtime_config(families, config, None)
}

pub(crate) fn embed_families_with_runtime_config(
    families: FeatureFamilies,
    config: &EmbeddingModelConfig,
    runtime_config: Option<&Config>,
) -> Vec<f32> {
    let dimensions = config.dimensions.max(1);
    let fallback_message = resolve_embedding_device(config.device);
    if let Some(message) = fallback_message {
        if let Some(config) = runtime_config {
            Stderr::print_debug(config, message);
        }
    }
    let semantic = project_features(&families.semantic, dimensions, 0x5E9A_0000);
    let control_flow = project_features(&families.control_flow, dimensions, 0x5E9A_0001);
    let sequence = project_features(&families.sequence, dimensions, 0x5E9A_0002);

    let mut vector = vec![0.0f32; dimensions];
    for index in 0..dimensions {
        vector[index] = semantic[index] * families.semantic_weight
            + control_flow[index] * families.control_flow_weight
            + sequence[index] * families.sequence_weight;
    }
    smooth_vector(&mut vector);
    normalize_l2(&mut vector);
    vector
}

fn project_features(features: &[f32], dimensions: usize, seed: u64) -> Vec<f32> {
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

    values
}

fn resolve_embedding_device(device_preference: EmbeddingDevice) -> Option<String> {
    match device_preference {
        EmbeddingDevice::Cpu => None,
        other => Some(format!(
            "llvm embedding device={} is not supported yet; using cpu",
            other.as_str()
        )),
    }
}

impl EmbeddingDevice {
    fn as_str(self) -> &'static str {
        match self {
            EmbeddingDevice::Cpu => "cpu",
            EmbeddingDevice::Gpu => "gpu",
            EmbeddingDevice::Cuda => "cuda",
            EmbeddingDevice::Vulkan => "vulkan",
            EmbeddingDevice::Metal => "metal",
            EmbeddingDevice::WebGpu => "webgpu",
            EmbeddingDevice::Rocm => "rocm",
        }
    }
}

fn smooth_vector(vector: &mut [f32]) {
    for value in vector.iter_mut() {
        *value = value.signum() * value.abs().sqrt();
    }
}
