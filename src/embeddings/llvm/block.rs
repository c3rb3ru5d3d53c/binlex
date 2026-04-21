use super::{
    FeatureFamilies, canonical_block_bitcode, configured_model,
    control_flow_features_for_block_module, embed_families_with_runtime_config,
    parse_module_from_bitcode, primary_defined_function, semantic_features_from_module,
    sequence_features_from_tokens,
};
use crate::controlflow::Block;
use inkwell::context::Context;
use std::io::Error;

pub fn embed(block: &Block<'_>) -> Result<Vec<f32>, Error> {
    let bitcode = canonical_block_bitcode(block)?;
    let context = Context::create();
    let module = parse_module_from_bitcode(&context, &bitcode)?;
    let llvm_function =
        primary_defined_function(&module).ok_or_else(|| Error::other("missing lifted block"))?;
    let (semantic, opcodes, helpers) = semantic_features_from_module(llvm_function);
    let control_flow = control_flow_features_for_block_module(llvm_function);
    let sequence = sequence_features_from_tokens(&opcodes, &helpers);
    let families = FeatureFamilies {
        semantic,
        control_flow,
        sequence,
        semantic_weight: 0.60,
        control_flow_weight: 0.15,
        sequence_weight: 0.25,
    };
    Ok(embed_families_with_runtime_config(
        families,
        &configured_model(&block.cfg.config),
        Some(&block.cfg.config),
    ))
}
