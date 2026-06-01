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

use crate::Configuration;
use crate::config::RAYON_WORKER_STACK_SIZE;
use crate::controlflow::{Function, Graph};
use crate::formats::Image;
use crate::ir::hir::HirFunction;
use crate::ir::lir::LirFunction;
use crate::ir::mir::{
    MirBlockParameter, MirControlTarget, MirFunction, MirOperationKind, MirType, MirValue,
};
use rayon::ThreadPoolBuilder;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Error;

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
}

pub struct Decompiler<'a> {
    graph: &'a Graph,
    image: &'a Image,
    configuration: Configuration,
    backend: DecompilerBackend,
}

impl<'a> Decompiler<'a> {
    pub fn new(
        graph: &'a Graph,
        image: &'a Image,
        configuration: Configuration,
        backend: DecompilerBackend,
    ) -> Self {
        Self {
            graph,
            image,
            configuration,
            backend,
        }
    }

    pub fn graph(&self) -> &'a Graph {
        self.graph
    }

    pub fn image(&self) -> &'a Image {
        self.image
    }

    pub fn configuration(&self) -> &Configuration {
        &self.configuration
    }

    pub fn backend(&self) -> DecompilerBackend {
        self.backend
    }

    pub fn function(&self, address: u64) -> Option<Function<'a>> {
        self.graph.get_function(address)
    }

    fn optimize_lir(&self, lir: &mut LirFunction) {
        if self.configuration.decompiler.lir.optimize.enabled {
            lir.optimize();
        }
    }

    fn optimize_mir(&self, mir: &mut MirFunction) {
        if self.configuration.decompiler.mir.optimize.enabled {
            mir.optimize();
        }
    }

    fn decompile_inner(&self, function: &Function<'a>) -> Result<DecompiledFunction, Error> {
        match self.backend {
            DecompilerBackend::Default => {
                let mut lir = function.lir()?;
                self.optimize_lir(&mut lir);
                let mut mir = function.mir()?;
                self.optimize_mir(&mut mir);
                function.trim_mir_call_arguments(&mut mir, &self.graph.symbols())?;
                let hir = HirFunction::from_mir(None, &mir)
                    .map_err(|error| Error::other(error.to_string()))?;
                Ok(DecompiledFunction {
                    address: function.address(),
                    lir,
                    mir,
                    hir,
                })
            }
        }
    }

    pub fn decompile_function(&self, address: u64) -> Result<Option<DecompiledFunction>, Error> {
        let Some(function) = self.function(address) else {
            return Ok(None);
        };
        self.decompile_inner(&function).map(Some)
    }

    pub fn decompile(&self) -> Result<Vec<DecompiledFunction>, Error> {
        let addresses = self
            .graph
            .functions()
            .into_iter()
            .map(|function| function.address())
            .collect::<Vec<_>>();

        let threads = self.configuration.resolved_threads();
        let mut functions = if threads <= 1 || addresses.len() <= 1 {
            addresses
                .into_iter()
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
                    .into_par_iter()
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
        rewrite_entry_signature(&mut functions[*index].mir, arity, &signature.types);
    }

    trim_local_calls_to_reconciled_signatures(functions, &observed);
    for function in functions {
        function.hir = HirFunction::from_mir(None, &function.mir)
            .map_err(|error| Error::other(error.to_string()))?;
    }

    Ok(())
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

fn rewrite_entry_signature(
    mir: &mut MirFunction,
    arity: usize,
    observed_types: &[Option<MirType>],
) {
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

    mir.entry_parameters = parameters.clone();
    if let Some(entry_block) = mir.blocks_mut().first_mut() {
        entry_block.parameters = parameters;
    }
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
