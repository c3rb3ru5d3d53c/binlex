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
use crate::ir::lir::LirFunction;
use crate::ir::mir::MirFunction;
use rayon::ThreadPoolBuilder;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
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
}

pub struct Decompiler<'a> {
    graph: &'a Graph,
    configuration: Configuration,
    backend: DecompilerBackend,
}

impl<'a> Decompiler<'a> {
    pub fn new(graph: &'a Graph, configuration: Configuration, backend: DecompilerBackend) -> Self {
        Self {
            graph,
            configuration,
            backend,
        }
    }

    pub fn graph(&self) -> &'a Graph {
        self.graph
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
                Ok(DecompiledFunction {
                    address: function.address(),
                    lir,
                    mir,
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
        if threads <= 1 || addresses.len() <= 1 {
            return addresses
                .into_iter()
                .map(|address| {
                    let function = Function::new(address, self.graph)?;
                    self.decompile_inner(&function)
                })
                .collect();
        }

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
                .collect()
        })
    }
}
