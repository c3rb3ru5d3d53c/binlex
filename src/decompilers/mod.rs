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
use crate::irs::lir::LirFunction;
use rayon::ThreadPoolBuilder;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
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
            DecompilerBackend::Default => Ok(DecompiledFunction {
                address: function.address(),
                lir: function.build_lir(&self.graph.symbols())?,
            }),
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

        functions.sort_by_key(|function| function.address);
        Ok(functions)
    }

    fn decompile_to_graph_cache(&self, addresses: &[u64]) -> Result<(), Error> {
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
        Ok(())
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
        self.graph.block_reference_maps();
        self.graph.function_reference_maps();
        self.decompile_to_graph_cache(&addresses)?;
        if let Some(started_at) = started_at {
            Stderr::print_debug(
                self.configuration(),
                format!(
                    "[timing] decompiler.decompile functions={} elapsed={:.3} ms",
                    addresses.len(),
                    started_at.elapsed().as_secs_f64() * 1000.0,
                ),
            );
        }
        Ok(())
    }
}
