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

use crate::controlflow::{Function, Graph};
use crate::irs::ast::PyAstFunction;
use crate::irs::hir::PyHirFunction;
use crate::irs::lir::LirFunction as PyLirFunction;
use crate::irs::mir::PyMirFunction;
use binlex::decompilers::{DecompiledFunction, Decompiler as InnerDecompiler, DecompilerBackend};
use pyo3::exceptions::{PyRuntimeError, PyTypeError};
use pyo3::prelude::*;
use std::sync::Arc;
use std::sync::Mutex;

#[pyclass]
pub struct Decompiler {
    graph: Py<Graph>,
    graph_inner: Arc<Mutex<binlex::controlflow::Graph>>,
    backend: DecompilerBackend,
}

impl Decompiler {
    fn decompile_artifact_to_python(
        py: Python<'_>,
        artifact: DecompiledFunction,
    ) -> PyResult<(
        u64,
        Py<PyLirFunction>,
        Py<PyMirFunction>,
        Py<PyHirFunction>,
        Py<PyAstFunction>,
    )> {
        Ok((
            artifact.address,
            Py::new(py, PyLirFunction::from_inner(artifact.lir))?,
            Py::new(py, PyMirFunction::from_inner(artifact.mir))?,
            Py::new(py, PyHirFunction::from_inner(artifact.hir))?,
            Py::new(py, PyAstFunction::from_inner(artifact.ast))?,
        ))
    }
}

#[pymethods]
impl Decompiler {
    #[new]
    #[pyo3(text_signature = "(graph, backend='default')")]
    pub fn new(py: Python<'_>, graph: Py<Graph>, backend: Option<String>) -> PyResult<Self> {
        let graph_ref = graph.borrow(py);
        let graph_inner = graph_ref.inner.clone();
        drop(graph_ref);
        let backend = match backend.as_deref().unwrap_or("default") {
            "default" => DecompilerBackend::Default,
            other => {
                return Err(PyTypeError::new_err(format!(
                    "unsupported decompiler backend: {other}"
                )));
            }
        };
        Ok(Self {
            graph,
            graph_inner,
            backend,
        })
    }

    #[getter]
    pub fn get_graph(&self, py: Python<'_>) -> Py<Graph> {
        self.graph.clone_ref(py)
    }

    #[getter]
    pub fn get_backend(&self) -> String {
        match self.backend {
            DecompilerBackend::Default => "default".to_string(),
        }
    }

    #[pyo3(text_signature = "($self, address)")]
    pub fn function(&self, py: Python<'_>, address: u64) -> PyResult<Option<Function>> {
        let cfg = self.graph.clone_ref(py);
        if self.graph_inner.lock().unwrap().function(address).is_none() {
            return Ok(None);
        }
        Ok(Some(Function::new(address, cfg)?))
    }

    #[pyo3(text_signature = "($self, address)")]
    pub fn decompile_function_artifacts(
        &self,
        py: Python<'_>,
        address: u64,
    ) -> PyResult<
        Option<(
            Py<PyLirFunction>,
            Py<PyMirFunction>,
            Py<PyHirFunction>,
            Py<PyAstFunction>,
        )>,
    > {
        let graph_inner = self.graph_inner.clone();
        let backend = self.backend;
        let graph = graph_inner.lock().unwrap();
        let artifact = InnerDecompiler::new(&graph, backend)
            .decompile_function(address)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        let Some(artifact) = artifact else {
            return Ok(None);
        };
        let (_, lir, mir, hir, ast) = Self::decompile_artifact_to_python(py, artifact)?;
        Ok(Some((lir, mir, hir, ast)))
    }

    #[pyo3(text_signature = "($self, address)")]
    pub fn decompile_function(&self, py: Python<'_>, address: u64) -> PyResult<Option<Function>> {
        let graph_inner = self.graph_inner.clone();
        let backend = self.backend;
        let graph = graph_inner.lock().unwrap();
        if InnerDecompiler::new(&graph, backend)
            .decompile_function(address)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?
            .is_none()
        {
            return Ok(None);
        }
        Ok(Some(Function::new(address, self.graph.clone_ref(py))?))
    }

    #[pyo3(text_signature = "($self)")]
    pub fn decompile_artifacts(
        &self,
        py: Python<'_>,
    ) -> PyResult<
        Vec<(
            u64,
            Py<PyLirFunction>,
            Py<PyMirFunction>,
            Py<PyHirFunction>,
            Py<PyAstFunction>,
        )>,
    > {
        let graph_inner = self.graph_inner.clone();
        let backend = self.backend;
        let graph = graph_inner.lock().unwrap();
        let artifacts = InnerDecompiler::new(&graph, backend)
            .decompile_artifacts()
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;

        artifacts
            .into_iter()
            .map(|artifact| Self::decompile_artifact_to_python(py, artifact))
            .collect()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn decompile(&self, py: Python<'_>) -> PyResult<Py<Self>> {
        let graph_inner = self.graph_inner.clone();
        let backend = self.backend;
        let graph = graph_inner.lock().unwrap();
        InnerDecompiler::new(&graph, backend)
            .decompile()
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(Py::new(
            py,
            Self {
                graph: self.graph.clone_ref(py),
                graph_inner: self.graph_inner.clone(),
                backend: self.backend,
            },
        )?)
    }
}

#[pymodule]
#[pyo3(name = "decompiler")]
pub fn decompiler_init(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Decompiler>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.decompilers.decompiler", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.decompilers.decompiler")?;
    Ok(())
}
