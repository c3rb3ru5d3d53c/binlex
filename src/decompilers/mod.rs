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

use crate::config::RAYON_WORKER_STACK_SIZE;
use crate::controlflow::{Function, Graph};
use crate::io::Stderr;
use crate::irs::ast::AstFunction;
use crate::irs::hir::HirFunction;
use crate::irs::lir::LirFunction;
use crate::irs::mir::{
    MirBlockParameter, MirControlTarget, MirFunction, MirOperationKind, MirType, MirValue,
};
use rayon::ThreadPoolBuilder;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Error;
use std::time::Instant;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecompilerBackend {
    #[default]
    Default,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecompiledFunction {
    pub address: u64,
    pub lir: LirFunction,
    pub mir: MirFunction,
    pub hir: HirFunction,
    pub ast: AstFunction,
}

pub type DecompiledFunctionState = Vec<u8>;

pub struct Decompiler<'a> {
    graph: &'a Graph,
    backend: DecompilerBackend,
}

impl<'a> Decompiler<'a> {
    pub fn new(graph: &'a Graph, backend: DecompilerBackend) -> Self {
        Self { graph, backend }
    }

    pub fn graph(&self) -> &'a Graph {
        self.graph
    }

    pub fn image(&self) -> &'a crate::formats::Image {
        self.graph.image()
    }

    pub fn configuration(&self) -> &crate::Configuration {
        &self.graph.config
    }

    pub fn backend(&self) -> DecompilerBackend {
        self.backend
    }

    pub fn function(&self, address: u64) -> Option<Function<'a>> {
        self.graph.function(address)
    }

    fn decompile_inner(&self, function: &Function<'a>) -> Result<DecompiledFunction, Error> {
        match self.backend {
            DecompilerBackend::Default => {
                let lir = function.lir()?;
                let mir = function.mir()?;
                let hir = HirFunction::from_mir(None, &mir)
                    .map_err(|error| Error::other(error.to_string()))?;
                let ast = AstFunction::from_hir(&hir).with_image(self.image());
                Ok(DecompiledFunction {
                    address: function.address(),
                    lir,
                    mir,
                    hir,
                    ast,
                })
            }
        }
    }

    pub fn decompile_function(&self, address: u64) -> Result<Option<DecompiledFunction>, Error> {
        let Some(function) = self.function(address) else {
            return Ok(None);
        };
        let artifact = self.decompile_inner(&function)?;
        self.graph.cache_decompilation(&artifact)?;
        Ok(Some(artifact))
    }

    fn function_addresses(&self) -> Vec<u64> {
        self.graph
            .functions()
            .into_iter()
            .map(|function| function.address())
            .collect::<Vec<_>>()
    }

    fn decompile_artifacts_inner(
        &self,
        addresses: &[u64],
    ) -> Result<Vec<DecompiledFunction>, Error> {
        let threads = self.configuration().resolved_threads();
        let mut functions = if threads <= 1 || addresses.len() <= 1 {
            addresses
                .iter()
                .copied()
                .map(|address| {
                    let function = Function::new(address, self.graph)?;
                    self.decompile_inner(&function)
                })
                .collect::<Result<Vec<_>, _>>()?
        } else {
            let pool = ThreadPoolBuilder::new()
                .num_threads(threads)
                .stack_size(RAYON_WORKER_STACK_SIZE)
                .build()
                .map_err(|error| Error::other(error.to_string()))?;

            pool.install(|| {
                addresses
                    .par_iter()
                    .copied()
                    .map(|address| {
                        let function = Function::new(address, self.graph)?;
                        self.decompile_inner(&function)
                    })
                    .collect::<Result<Vec<_>, _>>()
            })?
        };

        reconcile_local_function_signatures(&mut functions)?;
        Ok(functions)
    }

    fn decompile_to_graph_cache(&self, addresses: &[u64]) -> Result<(), Error> {
        let debug_enabled = self.configuration().debug;
        let started_at = if debug_enabled {
            Some(Instant::now())
        } else {
            None
        };
        let threads = self.configuration().resolved_threads();
        if threads <= 1 || addresses.len() <= 1 {
            for address in addresses {
                let function = Function::new(*address, self.graph)?;
                let artifact = self.decompile_inner(&function)?;
                self.graph.cache_decompilation(&artifact)?;
            }
        } else {
            let pool = ThreadPoolBuilder::new()
                .num_threads(threads)
                .stack_size(RAYON_WORKER_STACK_SIZE)
                .build()
                .map_err(|error| Error::other(error.to_string()))?;

            pool.install(|| {
                addresses.par_iter().copied().try_for_each(|address| {
                    let function = Function::new(address, self.graph)?;
                    let artifact = self.decompile_inner(&function)?;
                    self.graph.cache_decompilation(&artifact)
                })
            })?
        }

        if let Some(started_at) = started_at {
            Stderr::print_debug(
                self.configuration(),
                format!(
                    "[timing] decompiler.decompile.functions functions={} threads={} cache={:.3} ms",
                    addresses.len(),
                    threads,
                    started_at.elapsed().as_secs_f64() * 1000.0,
                ),
            );
        }

        reconcile_local_function_signatures_cached(self.graph, addresses)
    }

    pub fn decompile_artifacts(&self) -> Result<Vec<DecompiledFunction>, Error> {
        let addresses = self.function_addresses();
        let functions = self.decompile_artifacts_inner(&addresses)?;
        for function in &functions {
            self.graph.cache_decompilation(function)?;
        }
        Ok(functions)
    }

    pub fn decompile(&self) -> Result<(), Error> {
        let started_at = if self.configuration().debug {
            Some(Instant::now())
        } else {
            None
        };
        let addresses = self.function_addresses();
        if let Some(started_at) = started_at {
            Stderr::print_debug(
                self.configuration(),
                format!(
                    "[timing] decompiler.decompile.collect functions={} elapsed={:.3} ms",
                    addresses.len(),
                    started_at.elapsed().as_secs_f64() * 1000.0,
                ),
            );
        }
        self.decompile_to_graph_cache(&addresses)?;
        if self.configuration().debug {
            Stderr::print_debug(
                self.configuration(),
                format!(
                    "[timing] decompiler.decompile.complete functions={}",
                    addresses.len(),
                ),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct ObservedSignature {
    arities: BTreeSet<usize>,
    types: Vec<Option<MirType>>,
}

impl ObservedSignature {
    fn new() -> Self {
        Self {
            arities: BTreeSet::new(),
            types: Vec::new(),
        }
    }

    fn observe(&mut self, arguments: &[MirValue]) {
        self.arities.insert(arguments.len());
        if self.types.len() < arguments.len() {
            self.types.resize(arguments.len(), None);
        }
        for (index, argument) in arguments.iter().enumerate() {
            merge_type(&mut self.types[index], value_type(argument));
        }
    }

    fn reconciled_arity(&self) -> Option<usize> {
        if self.arities.len() == 1 {
            self.arities.iter().next().copied()
        } else {
            None
        }
    }
}

fn reconcile_local_function_signatures(functions: &mut [DecompiledFunction]) -> Result<(), Error> {
    let targets = local_target_indices(functions);
    let observed = observed_local_signatures(functions, &targets);
    if observed.is_empty() {
        return Ok(());
    }

    for (target, index) in &targets {
        let Some(signature) = observed.get(target) else {
            continue;
        };
        let Some(arity) = signature.reconciled_arity() else {
            continue;
        };
        let _ = rewrite_entry_signature(&mut functions[*index].mir, arity, &signature.types);
    }

    trim_local_calls_to_reconciled_signatures(functions, &observed);
    for function in functions {
        function.hir = HirFunction::from_mir(None, &function.mir)
            .map_err(|error| Error::other(error.to_string()))?;
    }

    Ok(())
}

fn reconcile_local_function_signatures_cached(
    graph: &Graph,
    addresses: &[u64],
) -> Result<(), Error> {
    let debug_enabled = graph.config.debug;
    let total_started_at = if debug_enabled {
        Some(Instant::now())
    } else {
        None
    };
    let targets_started_at = if debug_enabled {
        Some(Instant::now())
    } else {
        None
    };
    let targets = local_target_addresses(graph, addresses)?;
    if let Some(started_at) = targets_started_at {
        Stderr::print_debug(
            &graph.config,
            format!(
                "[timing] decompiler.reconcile.targets functions={} targets={} elapsed={:.3} ms",
                addresses.len(),
                targets.len(),
                started_at.elapsed().as_secs_f64() * 1000.0,
            ),
        );
    }

    let observe_started_at = if debug_enabled {
        Some(Instant::now())
    } else {
        None
    };
    let observed = observed_local_signatures_cached(graph, addresses, &targets)?;
    if let Some(started_at) = observe_started_at {
        Stderr::print_debug(
            &graph.config,
            format!(
                "[timing] decompiler.reconcile.observe functions={} signatures={} elapsed={:.3} ms",
                addresses.len(),
                observed.len(),
                started_at.elapsed().as_secs_f64() * 1000.0,
            ),
        );
    }
    if observed.is_empty() {
        if let Some(started_at) = total_started_at {
            Stderr::print_debug(
                &graph.config,
                format!(
                    "[timing] decompiler.reconcile.total functions={} elapsed={:.3} ms",
                    addresses.len(),
                    started_at.elapsed().as_secs_f64() * 1000.0,
                ),
            );
        }
        return Ok(());
    }

    let rewrite_started_at = if debug_enabled {
        Some(Instant::now())
    } else {
        None
    };
    let threads = graph.config.resolved_threads();
    let rewritten = if threads <= 1 || addresses.len() <= 1 {
        addresses
            .iter()
            .copied()
            .try_fold(0usize, |rewritten, address| {
                Ok::<usize, Error>(
                    rewritten + usize::from(reconcile_cached_function(graph, address, &observed)?),
                )
            })?
    } else {
        let pool = ThreadPoolBuilder::new()
            .num_threads(threads)
            .stack_size(RAYON_WORKER_STACK_SIZE)
            .build()
            .map_err(|error| Error::other(error.to_string()))?;

        pool.install(|| {
            addresses
                .par_iter()
                .copied()
                .map(|address| {
                    reconcile_cached_function(graph, address, &observed).map(usize::from)
                })
                .try_reduce(|| 0usize, |left, right| Ok(left + right))
        })?
    };

    if let Some(started_at) = rewrite_started_at {
        Stderr::print_debug(
            &graph.config,
            format!(
                "[timing] decompiler.reconcile.rewrite functions={} rewritten={} elapsed={:.3} ms",
                addresses.len(),
                rewritten,
                started_at.elapsed().as_secs_f64() * 1000.0,
            ),
        );
    }

    if let Some(started_at) = total_started_at {
        Stderr::print_debug(
            &graph.config,
            format!(
                "[timing] decompiler.reconcile.total functions={} elapsed={:.3} ms",
                addresses.len(),
                started_at.elapsed().as_secs_f64() * 1000.0,
            ),
        );
    }

    Ok(())
}

fn reconcile_cached_function(
    graph: &Graph,
    address: u64,
    observed: &BTreeMap<String, ObservedSignature>,
) -> Result<bool, Error> {
    let Some(mut function) = graph.cached_decompilation(address)? else {
        return Ok(false);
    };

    let mut changed = false;
    for target in local_target_names(&function) {
        let Some(signature) = observed.get(&target) else {
            continue;
        };
        let Some(arity) = signature.reconciled_arity() else {
            continue;
        };
        changed |= rewrite_entry_signature(&mut function.mir, arity, &signature.types);
    }

    changed |= trim_local_calls_to_reconciled_signature(&mut function, observed);
    if !changed {
        return Ok(false);
    }

    function.hir = HirFunction::from_mir(None, &function.mir)
        .map_err(|error| Error::other(error.to_string()))?;
    function.ast = AstFunction::from_hir(&function.hir).with_image(graph.image());
    graph.cache_decompilation(&function)?;
    Ok(true)
}

fn local_target_indices(functions: &[DecompiledFunction]) -> BTreeMap<String, usize> {
    let mut targets = BTreeMap::new();
    for (index, function) in functions.iter().enumerate() {
        targets.insert(format!("function_{:x}", function.address), index);
        if let Some(name) = &function.mir.name {
            targets.insert(name.clone(), index);
        }
        if let Some(name) = &function.lir.name {
            targets.insert(name.clone(), index);
        }
    }
    targets
}

fn local_target_addresses(
    graph: &Graph,
    addresses: &[u64],
) -> Result<BTreeMap<String, u64>, Error> {
    let mut targets = BTreeMap::new();
    for address in addresses {
        let Some(function) = graph.cached_decompilation(*address)? else {
            continue;
        };
        for target in local_target_names(&function) {
            targets.insert(target, *address);
        }
    }
    Ok(targets)
}

fn local_target_names(function: &DecompiledFunction) -> Vec<String> {
    let mut targets = vec![format!("function_{:x}", function.address)];
    if let Some(name) = &function.mir.name {
        targets.push(name.clone());
    }
    if let Some(name) = &function.lir.name {
        targets.push(name.clone());
    }
    targets
}

fn observed_local_signatures(
    functions: &[DecompiledFunction],
    targets: &BTreeMap<String, usize>,
) -> BTreeMap<String, ObservedSignature> {
    let mut observed = BTreeMap::<String, ObservedSignature>::new();
    for function in functions {
        for block in function.mir.blocks() {
            for operation in &block.operations {
                let MirOperationKind::Call {
                    target: MirControlTarget::Direct(target),
                    arguments,
                    ..
                } = &operation.kind
                else {
                    continue;
                };
                if !targets.contains_key(target) {
                    continue;
                }
                observed
                    .entry(target.clone())
                    .or_insert_with(ObservedSignature::new)
                    .observe(arguments);
            }
        }
    }
    observed
}

fn observed_local_signatures_cached(
    graph: &Graph,
    addresses: &[u64],
    targets: &BTreeMap<String, u64>,
) -> Result<BTreeMap<String, ObservedSignature>, Error> {
    let mut observed = BTreeMap::<String, ObservedSignature>::new();
    for address in addresses {
        let Some(function) = graph.cached_decompilation(*address)? else {
            continue;
        };
        observe_local_signatures_from_mir(&function.mir, targets, &mut observed);
    }
    Ok(observed)
}

fn observe_local_signatures_from_mir(
    mir: &MirFunction,
    targets: &BTreeMap<String, u64>,
    observed: &mut BTreeMap<String, ObservedSignature>,
) {
    for block in mir.blocks() {
        for operation in &block.operations {
            let MirOperationKind::Call {
                target: MirControlTarget::Direct(target),
                arguments,
                ..
            } = &operation.kind
            else {
                continue;
            };
            if !targets.contains_key(target) {
                continue;
            }
            observed
                .entry(target.clone())
                .or_insert_with(ObservedSignature::new)
                .observe(arguments);
        }
    }
}

fn rewrite_entry_signature(
    mir: &mut MirFunction,
    arity: usize,
    observed_types: &[Option<MirType>],
) -> bool {
    let mut parameters = Vec::with_capacity(arity);
    let mut used_names = BTreeSet::<String>::new();
    for index in 0..arity {
        let existing = mir.entry_parameters.get(index);
        let name = existing
            .and_then(|parameter| parameter.name.clone())
            .filter(|name| used_names.insert(name.clone()))
            .unwrap_or_else(|| next_argument_name(&mut used_names));
        let ty = observed_types
            .get(index)
            .and_then(Clone::clone)
            .or_else(|| existing.map(|parameter| parameter.ty.clone()))
            .unwrap_or_else(|| MirType::integer(64));
        parameters.push(MirBlockParameter::new(Some(name), ty));
    }

    if mir.entry_parameters == parameters
        && mir
            .blocks()
            .first()
            .is_none_or(|entry_block| entry_block.parameters == parameters)
    {
        return false;
    }

    mir.entry_parameters = parameters.clone();
    if let Some(entry_block) = mir.blocks_mut().first_mut() {
        entry_block.parameters = parameters;
    }
    true
}

fn next_argument_name(used_names: &mut BTreeSet<String>) -> String {
    for index in 0.. {
        let name = format!("arg{index}");
        if used_names.insert(name.clone()) {
            return name;
        }
    }
    unreachable!("unbounded argument name search")
}

fn trim_local_calls_to_reconciled_signatures(
    functions: &mut [DecompiledFunction],
    observed: &BTreeMap<String, ObservedSignature>,
) {
    let arities = observed
        .iter()
        .filter_map(|(target, signature)| signature.reconciled_arity().map(|arity| (target, arity)))
        .collect::<BTreeMap<_, _>>();

    for function in functions {
        for block in function.mir.blocks_mut() {
            for operation in &mut block.operations {
                let MirOperationKind::Call {
                    target: MirControlTarget::Direct(target),
                    arguments,
                    ..
                } = &mut operation.kind
                else {
                    continue;
                };
                let Some(arity) = arities.get(target).copied() else {
                    continue;
                };
                if arguments.len() > arity {
                    arguments.truncate(arity);
                }
            }
        }
    }
}

fn trim_local_calls_to_reconciled_signature(
    function: &mut DecompiledFunction,
    observed: &BTreeMap<String, ObservedSignature>,
) -> bool {
    let arities = observed
        .iter()
        .filter_map(|(target, signature)| signature.reconciled_arity().map(|arity| (target, arity)))
        .collect::<BTreeMap<_, _>>();

    let mut changed = false;
    for block in function.mir.blocks_mut() {
        for operation in &mut block.operations {
            let MirOperationKind::Call {
                target: MirControlTarget::Direct(target),
                arguments,
                ..
            } = &mut operation.kind
            else {
                continue;
            };
            let Some(arity) = arities.get(target).copied() else {
                continue;
            };
            if arguments.len() > arity {
                arguments.truncate(arity);
                changed = true;
            }
        }
    }
    changed
}

fn value_type(value: &MirValue) -> MirType {
    match value {
        MirValue::Named { ty, .. } | MirValue::Null { ty } | MirValue::Undef { ty } => ty.clone(),
        MirValue::Integer { bits, .. } => MirType::integer(*bits),
        MirValue::Boolean(_) => MirType::integer(1),
    }
}

fn merge_type(slot: &mut Option<MirType>, ty: MirType) {
    match slot {
        None => *slot = Some(ty),
        Some(existing) if *existing == ty => {}
        Some(existing) => merge_mir_type(existing, ty),
    }
}

fn merge_mir_type(existing: &mut MirType, incoming: MirType) {
    match (existing, incoming) {
        (MirType::Integer(existing_bits), MirType::Integer(bits))
        | (MirType::Float(existing_bits), MirType::Float(bits)) => {
            *existing_bits = (*existing_bits).max(bits);
        }
        (MirType::Pointer { pointee: existing }, MirType::Pointer { pointee }) => {
            merge_mir_type(existing.as_mut(), *pointee);
        }
        (existing, incoming) if matches!(existing, MirType::Void) => {
            *existing = incoming;
        }
        _ => {}
    }
}
