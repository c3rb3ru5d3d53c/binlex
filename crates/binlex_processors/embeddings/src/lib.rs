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

/*
Weights:

- functions = 0.50 semantic/dataflow + 0.30 control-flow + 0.20 sequence/subgraph
- blocks = 0.60 semantic/dataflow + 0.15 control-flow + 0.25 sequence/subgraph
*/

use binlex::Config;
use binlex::config::{
    ConfigProcessor, ConfigProcessorTarget, ConfigProcessorTransport, ConfigProcessorTransports,
};
use binlex::controlflow::{Block, Function, Graph, GraphSnapshot};
use binlex::core::Architecture;
use binlex::core::{OperatingSystem, Transport};
use binlex::io::Stderr;
use binlex::lifters::llvm::Lifter as LlvmLifter;
use binlex::math::stats::normalize_l2;
use binlex::processor::{
    GraphProcessor, GraphProcessorFanout, OnGraphOptions, ProcessorContext,
    external_processor_registration,
};
use binlex::runtime::{Processor, ProcessorError};
use burn::tensor::{Tensor, TensorData};
use burn::{Dispatch, DispatchDevice};
use inkwell::context::Context;
use inkwell::memory_buffer::MemoryBuffer;
use inkwell::module::Module;
use inkwell::values::{BasicValue, CallSiteValue, FunctionValue, InstructionOpcode, Operand};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::hash::{Hash, Hasher};
use std::io::Error;
use std::sync::OnceLock;
use twox_hash::XxHash64;

const DEFAULT_DIMENSIONS: usize = 64;
const HASH_BUCKETS: usize = 64;
const SEQUENCE_BUCKETS: usize = 96;
const DEGREE_BUCKETS: usize = 8;

#[derive(Serialize, Deserialize, Clone)]
pub struct EmbeddingsRequest {
    #[serde(default)]
    pub dimensions: Option<usize>,
    #[serde(default)]
    pub device: Option<String>,
    #[serde(default)]
    pub threads: Option<usize>,
    pub graph: GraphSnapshot,
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

struct FeatureFamilies {
    semantic: Vec<f32>,
    control_flow: Vec<f32>,
    sequence: Vec<f32>,
    semantic_weight: f32,
    control_flow_weight: f32,
    sequence_weight: f32,
}

static AUTO_GPU_DEVICE: OnceLock<EmbeddingDevice> = OnceLock::new();

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

fn canonical_function_bitcode(function: &Function<'_>) -> Result<Vec<u8>, Error> {
    let mut lifter = LlvmLifter::new(function.cfg.config.clone());
    lifter.lift_function(function)?;
    let optimized = optimize_lifter(lifter)?;
    Ok(optimized.bitcode())
}

fn canonical_block_bitcode(block: &Block<'_>) -> Result<Vec<u8>, Error> {
    let mut lifter = LlvmLifter::new(block.cfg.config.clone());
    lifter.lift_block(block)?;
    let optimized = optimize_lifter(lifter)?;
    Ok(optimized.bitcode())
}

fn parse_module_from_bitcode<'ctx>(
    context: &'ctx Context,
    bitcode: &[u8],
) -> Result<Module<'ctx>, Error> {
    let buffer = MemoryBuffer::create_from_memory_range_copy(bitcode, "binlex-embedding.bc");
    Module::parse_bitcode_from_buffer(&buffer, context)
        .map_err(|error| Error::other(error.to_string()))
}

fn primary_defined_function<'ctx>(module: &Module<'ctx>) -> Option<FunctionValue<'ctx>> {
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

fn semantic_features_from_module<'ctx>(
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
                    Some(Operand::Block(_)) => {
                        block_operands += 1.0;
                    }
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

    let mut dataflow = Vec::new();
    let phi_count = opcodes
        .iter()
        .filter(|opcode| opcode.as_str() == "phi")
        .count() as f32;
    let select_count = opcodes
        .iter()
        .filter(|opcode| opcode.as_str() == "select")
        .count() as f32;
    let load_count = opcodes
        .iter()
        .filter(|opcode| opcode.as_str() == "load")
        .count() as f32;
    let store_count = opcodes
        .iter()
        .filter(|opcode| opcode.as_str() == "store")
        .count() as f32;
    let gep_count = opcodes
        .iter()
        .filter(|opcode| opcode.as_str() == "getelementptr")
        .count() as f32;
    let alloca_count = opcodes
        .iter()
        .filter(|opcode| opcode.as_str() == "alloca")
        .count() as f32;
    let cast_count = opcodes
        .iter()
        .filter(|opcode| {
            matches!(
                opcode.as_str(),
                "trunc" | "zext" | "sext" | "bitcast" | "ptrtoint" | "inttoptr"
            )
        })
        .count() as f32;
    let arithmetic_count = opcodes
        .iter()
        .filter(|opcode| {
            matches!(
                opcode.as_str(),
                "add" | "sub" | "mul" | "udiv" | "sdiv" | "urem" | "srem"
            )
        })
        .count() as f32;
    let bitwise_count = opcodes
        .iter()
        .filter(|opcode| {
            matches!(
                opcode.as_str(),
                "and" | "or" | "xor" | "shl" | "lshr" | "ashr"
            )
        })
        .count() as f32;
    let compare_count = opcodes
        .iter()
        .filter(|opcode| matches!(opcode.as_str(), "icmp" | "fcmp"))
        .count() as f32;
    let call_count = opcodes
        .iter()
        .filter(|opcode| opcode.as_str() == "call")
        .count() as f32;
    let branch_count = opcodes
        .iter()
        .filter(|opcode| matches!(opcode.as_str(), "br" | "switch"))
        .count() as f32;
    let return_count = opcodes
        .iter()
        .filter(|opcode| opcode.as_str() == "ret")
        .count() as f32;
    let unreachable_count = opcodes
        .iter()
        .filter(|opcode| opcode.as_str() == "unreachable")
        .count() as f32;

    for value in [
        phi_count,
        select_count,
        load_count,
        store_count,
        gep_count,
        alloca_count,
        cast_count,
        arithmetic_count,
        bitwise_count,
        compare_count,
        call_count,
        branch_count,
        return_count,
        unreachable_count,
    ] {
        push_scaled(&mut dataflow, value, instruction_count);
    }

    let helper_count = helpers.len().max(1) as f32;
    let mut call_features = Vec::new();
    push_scaled(&mut call_features, call_count, instruction_count);
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
    push_scaled(&mut memory_features, load_count, instruction_count);
    push_scaled(&mut memory_features, store_count, instruction_count);
    push_scaled(&mut memory_features, gep_count, instruction_count);
    push_scaled(&mut memory_features, alloca_count, instruction_count);
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
    push_scaled(&mut effect_features, branch_count, instruction_count);
    push_scaled(&mut effect_features, return_count, instruction_count);
    push_scaled(&mut effect_features, unreachable_count, instruction_count);
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

fn control_flow_features_for_function_module<'ctx>(function: FunctionValue<'ctx>) -> Vec<f32> {
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
        let mut instruction = block.get_first_instruction();
        let mut instruction_total = 0usize;
        while let Some(current) = instruction {
            instruction_total += 1;
            instruction = current.get_next_instruction();
        }
        instruction_counts.push(instruction_total as f32);

        let outdegree = *successor_counts.get(&name).unwrap_or(&0) as f32;
        outdegrees.push(outdegree);

        let terminator = block.get_terminator();
        if let Some(terminator) = terminator {
            match terminator.get_opcode() {
                InstructionOpcode::Br => {
                    if terminator.is_conditional().unwrap_or(false) {
                        conditional_count += 1;
                    }
                }
                InstructionOpcode::Switch => {
                    conditional_count += 1;
                    switch_count += 1;
                }
                InstructionOpcode::Invoke => {
                    invoke_count += 1;
                }
                InstructionOpcode::Return => {
                    return_count += 1;
                }
                InstructionOpcode::Unreachable => {
                    unreachable_count += 1;
                }
                _ => {}
            }

            for operand in terminator.get_operands() {
                if let Some(Operand::Block(target)) = operand {
                    let target_name = target.get_name().to_string_lossy().into_owned();
                    *indegree.entry(target_name.clone()).or_default() += 1;
                    if let (Some(source_index), Some(target_index)) =
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
        let indegree_value = *indegree.get(&name).unwrap_or(&0) as f32;
        indegrees.push(indegree_value);
        if *successor_counts.get(&name).unwrap_or(&0) == 0 {
            exit_count += 1;
        }
        if indegree_value > 0.0 && *successor_counts.get(&name).unwrap_or(&0) > 0 {
            loop_header_count += 1;
        }
    }

    let mut features = Vec::new();
    features.extend(numeric_histogram(&outdegrees, DEGREE_BUCKETS, 1.0));
    features.extend(numeric_histogram(&indegrees, DEGREE_BUCKETS, 1.0));
    features.extend(numeric_histogram(&instruction_counts, DEGREE_BUCKETS, 2.0));
    push_scaled(&mut features, function.count_basic_blocks() as f32, 256.0);
    push_scaled(&mut features, outdegrees.iter().sum::<f32>(), 1024.0);
    push_scaled(
        &mut features,
        (outdegrees.iter().sum::<f32>() - function.count_basic_blocks() as f32 + 2.0).max(0.0),
        512.0,
    );
    push_scaled(
        &mut features,
        instruction_counts.iter().sum::<f32>() / block_count,
        64.0,
    );
    push_scaled(&mut features, conditional_count as f32 / block_count, 1.0);
    push_scaled(&mut features, exit_count as f32 / block_count, 1.0);
    push_scaled(&mut features, return_count as f32 / block_count, 1.0);
    push_scaled(&mut features, unreachable_count as f32 / block_count, 1.0);
    push_scaled(&mut features, switch_count as f32 / block_count, 1.0);
    push_scaled(&mut features, invoke_count as f32 / block_count, 1.0);
    push_scaled(&mut features, backedge_count as f32, 256.0);
    push_scaled(&mut features, loop_header_count as f32 / block_count, 1.0);
    features
}

fn control_flow_features_for_block_module<'ctx>(function: FunctionValue<'ctx>) -> Vec<f32> {
    let block = function
        .get_first_basic_block()
        .expect("lifted block module should have an entry block");
    let mut instruction = block.get_first_instruction();
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

fn sequence_features_from_tokens(opcodes: &[String], helpers: &[String]) -> Vec<f32> {
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

fn function_features(function: &Function<'_>) -> Result<FeatureFamilies, Error> {
    let bitcode = canonical_function_bitcode(function)?;
    let context = Context::create();
    let module = parse_module_from_bitcode(&context, &bitcode)?;
    let llvm_function =
        primary_defined_function(&module).ok_or_else(|| Error::other("missing lifted function"))?;
    let (semantic, opcodes, helpers) = semantic_features_from_module(llvm_function);
    let control_flow = control_flow_features_for_function_module(llvm_function);
    let sequence = sequence_features_from_tokens(&opcodes, &helpers);
    Ok(FeatureFamilies {
        semantic,
        control_flow,
        sequence,
        semantic_weight: 0.50,
        control_flow_weight: 0.30,
        sequence_weight: 0.20,
    })
}

fn block_features(block: &Block<'_>) -> Result<FeatureFamilies, Error> {
    let bitcode = canonical_block_bitcode(block)?;
    let context = Context::create();
    let module = parse_module_from_bitcode(&context, &bitcode)?;
    let llvm_function =
        primary_defined_function(&module).ok_or_else(|| Error::other("missing lifted block"))?;
    let (semantic, opcodes, helpers) = semantic_features_from_module(llvm_function);
    let control_flow = control_flow_features_for_block_module(llvm_function);
    let sequence = sequence_features_from_tokens(&opcodes, &helpers);
    Ok(FeatureFamilies {
        semantic,
        control_flow,
        sequence,
        semantic_weight: 0.60,
        control_flow_weight: 0.15,
        sequence_weight: 0.25,
    })
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

fn embed_families(families: FeatureFamilies, config: &EmbeddingModelConfig) -> Vec<f32> {
    let dimensions = config.dimensions.max(1);
    let semantic = burn_project(&families.semantic, dimensions, 0x5E6A_6D1C, config.device);
    let control_flow = burn_project(
        &families.control_flow,
        dimensions,
        0xCF6C_F10A,
        config.device,
    );
    let sequence = burn_project(&families.sequence, dimensions, 0x5E9A_0001, config.device);

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

fn processor_config(config: &Config) -> Option<&ConfigProcessor> {
    config.processors.processor(EmbeddingsProcessor::NAME)
}

fn configured_dimensions(config: &Config) -> usize {
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

fn configured_device(config: &Config) -> EmbeddingDevice {
    parse_device(processor_config(config).and_then(|processor| processor.option_string("device")))
}

fn configured_threads(config: &Config) -> usize {
    processor_config(config)
        .and_then(|processor| processor.option_integer("threads"))
        .and_then(|value| usize::try_from(value).ok())
        .map(|value| {
            if value == 0 {
                config.resolved_threads()
            } else {
                value
            }
        })
        .unwrap_or_else(|| config.resolved_threads())
}

fn configured_device_from_context<C: ProcessorContext>(context: &C) -> String {
    context
        .processor(EmbeddingsProcessor::NAME)
        .and_then(|processor| processor.option_string("device"))
        .unwrap_or("cpu")
        .to_string()
}

fn configured_threads_from_context<C: ProcessorContext>(context: &C) -> usize {
    context
        .processor(EmbeddingsProcessor::NAME)
        .and_then(|processor| processor.option_integer("threads"))
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| *value > 0)
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|parallelism| parallelism.get())
                .unwrap_or(1)
        })
}

fn graph_from_snapshot(snapshot: GraphSnapshot) -> Result<Graph, ProcessorError> {
    let mut config = Config::default();
    config.processors.enabled = false;
    config.lifters.llvm.verify = false;
    Graph::from_snapshot(snapshot, config)
        .map_err(|error| ProcessorError::Protocol(error.to_string()))
}

fn embed_graph(
    graph: &Graph,
    config: &EmbeddingModelConfig,
    threads: usize,
) -> Result<GraphProcessorFanout, ProcessorError> {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads.max(1))
        .build()
        .map_err(|error: rayon::ThreadPoolBuildError| {
            ProcessorError::Protocol(error.to_string())
        })?;

    Ok(pool.install(|| GraphProcessorFanout {
        instructions: BTreeMap::new(),
        blocks: graph
            .blocks()
            .into_par_iter()
            .filter_map(|block| {
                let features = match block_features(&block) {
                    Ok(features) => features,
                    Err(error) => {
                        Stderr::print_debug(
                            &graph.config,
                            format!(
                                "embeddings skipped block address=0x{:x} error={}",
                                block.address(),
                                error
                            ),
                        );
                        return None;
                    }
                };
                Some((
                    block.address(),
                    json!({ "vector": embed_families(features, config) }),
                ))
            })
            .collect(),
        functions: graph
            .functions()
            .into_par_iter()
            .filter_map(|function| {
                let features = match function_features(&function) {
                    Ok(features) => features,
                    Err(error) => {
                        Stderr::print_debug(
                            &graph.config,
                            format!(
                                "embeddings skipped function address=0x{:x} error={}",
                                function.address(),
                                error
                            ),
                        );
                        return None;
                    }
                };
                Some((
                    function.address(),
                    json!({ "vector": embed_families(features, config) }),
                ))
            })
            .collect(),
    }))
}

impl Processor for EmbeddingsProcessor {
    const NAME: &'static str = "embeddings";
    type Request = EmbeddingsRequest;
    type Response = GraphProcessorFanout;

    fn execute(&self, request: Self::Request) -> Result<Self::Response, ProcessorError> {
        let config = EmbeddingModelConfig {
            dimensions: request.dimensions.unwrap_or(DEFAULT_DIMENSIONS),
            device: parse_device(request.device.as_deref()),
        };
        let threads = request
            .threads
            .map(|value| {
                if value == 0 {
                    std::thread::available_parallelism()
                        .map(|parallelism| parallelism.get())
                        .unwrap_or(1)
                } else {
                    value
                }
            })
            .unwrap_or_else(|| {
                std::thread::available_parallelism()
                    .map(|parallelism| parallelism.get())
                    .unwrap_or(1)
            });
        let graph = graph_from_snapshot(request.graph)?;
        embed_graph(&graph, &config, threads)
    }
}

impl GraphProcessor for EmbeddingsProcessor {
    fn on_graph_options() -> OnGraphOptions {
        OnGraphOptions {
            instructions: false,
            blocks: false,
            functions: false,
        }
    }

    fn request_message<C: ProcessorContext>(
        context: &C,
        data: Value,
    ) -> Result<Self::Request, ProcessorError> {
        if data.get("type").and_then(Value::as_str) != Some("graph") {
            return Err(ProcessorError::Protocol(
                "embeddings processor only supports graph-stage requests".to_string(),
            ));
        }
        let graph = serde_json::from_value::<GraphSnapshot>(data)
            .map_err(|error| ProcessorError::Serialization(error.to_string()))?;
        Ok(EmbeddingsRequest {
            dimensions: Some(configured_dimensions_from_context(context)),
            device: Some(configured_device_from_context(context)),
            threads: Some(configured_threads_from_context(context)),
            graph,
        })
    }

    fn on_graph(graph: &Graph) -> Option<GraphProcessorFanout> {
        let config = EmbeddingModelConfig {
            dimensions: configured_dimensions(&graph.config),
            device: configured_device(&graph.config),
        };
        embed_graph(graph, &config, configured_threads(&graph.config)).ok()
    }
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
        &[
            Architecture::AMD64,
            Architecture::I386,
            Architecture::ARM64,
            Architecture::CIL,
        ],
        &[Transport::IPC, Transport::HTTP],
        EmbeddingsProcessor::on_graph_options(),
        ConfigProcessor {
            enabled: false,
            instructions: ConfigProcessorTarget {
                enabled: false,
                options: BTreeMap::new(),
            },
            blocks: ConfigProcessorTarget {
                enabled: false,
                options: BTreeMap::new(),
            },
            functions: ConfigProcessorTarget {
                enabled: false,
                options: BTreeMap::new(),
            },
            graph: ConfigProcessorTarget {
                enabled: true,
                options: BTreeMap::new(),
            },
            complete: ConfigProcessorTarget {
                enabled: false,
                options: BTreeMap::new(),
            },
            options: BTreeMap::from([
                ("dimensions".to_string(), 64.into()),
                ("device".to_string(), "cpu".into()),
                ("threads".to_string(), 0.into()),
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
