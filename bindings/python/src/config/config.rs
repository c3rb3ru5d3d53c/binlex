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

use binlex::Configuration as InnerConfig;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyAny;
use serde_json::Value;
use std::sync::{Arc, Mutex};

fn json_value_to_py(py: Python<'_>, value: &Value) -> PyResult<Py<PyAny>> {
    let json_str =
        serde_json::to_string(value).map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
    let json_module = py.import("json")?;
    Ok(json_module.call_method1("loads", (json_str,))?.into())
}

fn py_to_json_value(py: Python<'_>, value: Py<PyAny>) -> PyResult<Value> {
    let json_module = py.import("json")?;
    let json_str = json_module
        .call_method1("dumps", (value,))?
        .extract::<String>()?;
    serde_json::from_str(&json_str).map_err(|error| PyValueError::new_err(error.to_string()))
}

#[pyclass]
pub struct ConfigHashing {
    inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigHashing {
    #[getter]
    pub fn get_tlsh(&self) -> ConfigTLSH {
        ConfigTLSH {
            inner: Arc::clone(&self.inner),
        }
    }

    #[getter]
    pub fn get_minhash(&self) -> ConfigMinhash {
        ConfigMinhash {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[pyclass]
pub struct ConfigTLSH {
    inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigTLSH {
    #[getter]
    pub fn get_minimum_byte_size(&self) -> usize {
        self.inner.lock().unwrap().hashing.tlsh.minimum_byte_size
    }

    #[setter]
    pub fn set_minimum_byte_size(&mut self, value: usize) {
        self.inner.lock().unwrap().hashing.tlsh.minimum_byte_size = value;
    }
}

#[pyclass]
pub struct ConfigMinhash {
    inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigMinhash {
    #[getter]
    pub fn get_number_of_hashes(&self) -> usize {
        self.inner.lock().unwrap().hashing.minhash.number_of_hashes
    }

    #[setter]
    pub fn set_number_of_hashes(&mut self, value: usize) {
        self.inner.lock().unwrap().hashing.minhash.number_of_hashes = value;
    }

    #[getter]
    pub fn get_shingle_size(&self) -> usize {
        self.inner.lock().unwrap().hashing.minhash.shingle_size
    }

    #[setter]
    pub fn set_shingle_size(&mut self, value: usize) {
        self.inner.lock().unwrap().hashing.minhash.shingle_size = value;
    }

    #[getter]
    pub fn get_maximum_byte_size_enabled(&self) -> bool {
        self.inner
            .lock()
            .unwrap()
            .hashing
            .minhash
            .maximum_byte_size_enabled
    }

    #[setter]
    pub fn set_maximum_byte_size_enabled(&mut self, value: bool) {
        self.inner
            .lock()
            .unwrap()
            .hashing
            .minhash
            .maximum_byte_size_enabled = value;
    }

    #[getter]
    pub fn get_maximum_byte_size(&self) -> usize {
        self.inner.lock().unwrap().hashing.minhash.maximum_byte_size
    }

    #[setter]
    pub fn set_maximum_byte_size(&mut self, value: usize) {
        self.inner.lock().unwrap().hashing.minhash.maximum_byte_size = value;
    }

    #[getter]
    pub fn get_seed(&self) -> u64 {
        self.inner.lock().unwrap().hashing.minhash.seed
    }

    #[setter]
    pub fn set_seed(&mut self, value: u64) {
        self.inner.lock().unwrap().hashing.minhash.seed = value;
    }
}

#[pyclass]
pub struct ConfigFunctions {
    inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigFunctions {
    #[getter]
    pub fn get_markov(&self) -> ConfigFunctionsMarkov {
        ConfigFunctionsMarkov {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[pyclass]
pub struct ConfigFunctionsMarkov {
    inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigFunctionsMarkov {
    #[getter]
    pub fn get_damping(&self) -> f64 {
        self.inner.lock().unwrap().functions.markov.damping
    }

    #[setter]
    pub fn set_damping(&mut self, value: f64) {
        self.inner.lock().unwrap().functions.markov.damping = value;
    }

    #[getter]
    pub fn get_tolerance(&self) -> f64 {
        self.inner.lock().unwrap().functions.markov.tolerance
    }

    #[setter]
    pub fn set_tolerance(&mut self, value: f64) {
        self.inner.lock().unwrap().functions.markov.tolerance = value;
    }

    #[getter]
    pub fn get_max_iterations(&self) -> usize {
        self.inner.lock().unwrap().functions.markov.max_iterations
    }

    #[setter]
    pub fn set_max_iterations(&mut self, value: usize) {
        self.inner.lock().unwrap().functions.markov.max_iterations = value;
    }
}

#[pyclass]
pub struct ConfigIrs {
    inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigIrs {
    #[getter]
    pub fn get_llvm(&self) -> ConfigIrsLLVM {
        ConfigIrsLLVM {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[pyclass]
pub struct ConfigIrsLLVM {
    inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigIrsLLVM {
    #[getter]
    pub fn get_module_name(&self) -> String {
        self.inner.lock().unwrap().irs.llvm.module_name.clone()
    }

    #[setter]
    pub fn set_module_name(&mut self, value: String) {
        self.inner.lock().unwrap().irs.llvm.module_name = value;
    }

    #[getter]
    pub fn get_verify(&self) -> bool {
        self.inner.lock().unwrap().irs.llvm.verify
    }

    #[setter]
    pub fn set_verify(&mut self, value: bool) {
        self.inner.lock().unwrap().irs.llvm.verify = value;
    }

    #[getter]
    pub fn get_mode(&self) -> String {
        match self.inner.lock().unwrap().irs.llvm.mode {
            binlex::irs::llvm::Mode::Reconstruct => "reconstruct",
            binlex::irs::llvm::Mode::Intrinsic => "intrinsic",
            binlex::irs::llvm::Mode::Lir => "lir",
        }
        .to_string()
    }

    #[setter]
    pub fn set_mode(&mut self, value: String) -> PyResult<()> {
        self.inner.lock().unwrap().irs.llvm.mode = match value.as_str() {
            "reconstruct" => binlex::irs::llvm::Mode::Reconstruct,
            "intrinsic" => binlex::irs::llvm::Mode::Intrinsic,
            "lir" => binlex::irs::llvm::Mode::Lir,
            _ => {
                return Err(PyRuntimeError::new_err(format!(
                    "invalid llvm mode: {value}"
                )))
            }
        };
        Ok(())
    }
}

#[pyclass]
pub struct ConfigEmbeddings {
    inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigEmbeddings {
    #[getter]
    pub fn get_llvm(&self) -> ConfigEmbeddingsLLVM {
        ConfigEmbeddingsLLVM {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[pyclass]
pub struct ConfigEmbeddingsLLVM {
    inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigEmbeddingsLLVM {
    #[getter]
    pub fn get_dimensions(&self) -> usize {
        self.inner.lock().unwrap().embeddings.llvm.dimensions
    }

    #[setter]
    pub fn set_dimensions(&mut self, value: usize) {
        self.inner.lock().unwrap().embeddings.llvm.dimensions = value.max(1);
    }

    #[getter]
    pub fn get_device(&self) -> String {
        self.inner.lock().unwrap().embeddings.llvm.device.clone()
    }

    #[setter]
    pub fn set_device(&mut self, value: String) {
        self.inner.lock().unwrap().embeddings.llvm.device = value;
    }
}

/// Top-level mutable configuration object for binlex analysis behavior.
#[pyclass]
pub struct Configuration {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl Configuration {
    #[new]
    /// Create a configuration object initialized with built-in defaults.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(InnerConfig::new())),
        }
    }

    pub fn clone(&self) -> Self {
        let inner = self.inner.lock().unwrap().clone();
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }

    #[pyo3(text_signature = "($self)")]
    pub fn snapshot(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        json_value_to_py(
            py,
            &serde_json::to_value(self.inner.lock().unwrap().clone())
                .map_err(|error| PyRuntimeError::new_err(error.to_string()))?,
        )
    }

    #[staticmethod]
    #[pyo3(text_signature = "(snapshot)")]
    pub fn from_snapshot(py: Python<'_>, snapshot: Py<PyAny>) -> PyResult<Self> {
        let inner = serde_json::from_value(py_to_json_value(py, snapshot)?)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    pub fn __getstate__(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        self.snapshot(py)
    }

    pub fn __setstate__(&mut self, py: Python<'_>, state: Py<PyAny>) -> PyResult<()> {
        *self.inner.lock().unwrap() = serde_json::from_value(py_to_json_value(py, state)?)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(())
    }

    #[getter]
    /// Return the configured analysis thread count. A value of 0 means automatic.
    pub fn get_threads(&self) -> usize {
        self.inner.lock().unwrap().threads
    }

    #[setter]
    pub fn set_threads(&mut self, value: usize) {
        self.inner.lock().unwrap().threads = value;
    }

    #[getter]
    /// Return whether debug logging is enabled.
    pub fn get_debug(&self) -> bool {
        self.inner.lock().unwrap().debug
    }

    #[setter]
    pub fn set_debug(&mut self, value: bool) {
        self.inner.lock().unwrap().debug = value;
    }

    #[getter]
    /// Return the hashing configuration group.
    pub fn get_hashing(&self) -> PyResult<ConfigHashing> {
        Ok(ConfigHashing {
            inner: Arc::clone(&self.inner),
        })
    }

    #[getter]
    /// Return the function analysis configuration group.
    pub fn get_functions(&self) -> PyResult<ConfigFunctions> {
        Ok(ConfigFunctions {
            inner: Arc::clone(&self.inner),
        })
    }

    #[getter]
    /// Return the memory-mapping configuration group.
    pub fn get_mmap(&self) -> PyResult<ConfigMmap> {
        Ok(ConfigMmap {
            inner: Arc::clone(&self.inner),
        })
    }

    #[getter]
    /// Return the disassembler configuration group.
    pub fn get_disassembler(&self) -> PyResult<ConfigDisassembler> {
        Ok(ConfigDisassembler {
            inner: Arc::clone(&self.inner),
        })
    }

    #[getter]
    /// Return the IR configuration group.
    pub fn get_irs(&self) -> PyResult<ConfigIrs> {
        Ok(ConfigIrs {
            inner: Arc::clone(&self.inner),
        })
    }

    #[getter]
    /// Return the embeddings configuration group.
    pub fn get_embeddings(&self) -> PyResult<ConfigEmbeddings> {
        Ok(ConfigEmbeddings {
            inner: Arc::clone(&self.inner),
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Load configuration values from the default config source.
    pub fn from_default(&mut self) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .from_default()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the serialized configuration text.
    pub fn to_string(&self) -> PyResult<String> {
        self.inner
            .lock()
            .unwrap()
            .to_string()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Print the serialized configuration text to stdout.
    pub fn print(&self) {
        self.inner.lock().unwrap().print()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn write_default(&self) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .write_default()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
    }

    #[pyo3(text_signature = "($self, file_path)")]
    pub fn write_to_file(&self, file_path: String) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .write_to_file(&file_path)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
    }
}

impl Default for Configuration {
    fn default() -> Self {
        Self::new()
    }
}

#[pyclass]
pub struct ConfigDisassembler {
    inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigDisassembler {
    #[getter]
    pub fn get_sweep(&self) -> ConfigDisassemblerSweep {
        ConfigDisassemblerSweep {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[pyclass]
pub struct ConfigDisassemblerSweep {
    inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigDisassemblerSweep {
    #[getter]
    pub fn get_enabled(&self) -> bool {
        self.inner.lock().unwrap().disassembler.sweep.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        self.inner.lock().unwrap().disassembler.sweep.enabled = value;
    }
}

#[pyclass]
pub struct ConfigMmap {
    inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigMmap {
    #[getter]
    pub fn get_directory(&self) -> String {
        self.inner.lock().unwrap().mmap.directory.clone()
    }

    #[setter]
    pub fn set_directory(&mut self, value: String) {
        self.inner.lock().unwrap().mmap.directory = value;
    }

    #[getter]
    pub fn get_cache(&self) -> ConfigMmapCache {
        ConfigMmapCache {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[pyclass]
pub struct ConfigMmapCache {
    inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigMmapCache {
    #[getter]
    pub fn get_enabled(&self) -> bool {
        self.inner.lock().unwrap().mmap.cache.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        self.inner.lock().unwrap().mmap.cache.enabled = value;
    }
}

pub fn register_config(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Configuration>()?;
    m.add_class::<ConfigHashing>()?;
    m.add_class::<ConfigTLSH>()?;
    m.add_class::<ConfigMinhash>()?;
    m.add_class::<ConfigFunctions>()?;
    m.add_class::<ConfigFunctionsMarkov>()?;
    m.add_class::<ConfigIrs>()?;
    m.add_class::<ConfigIrsLLVM>()?;
    m.add_class::<ConfigEmbeddings>()?;
    m.add_class::<ConfigEmbeddingsLLVM>()?;
    m.add_class::<ConfigDisassembler>()?;
    m.add_class::<ConfigDisassemblerSweep>()?;
    m.add_class::<ConfigMmap>()?;
    m.add_class::<ConfigMmapCache>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.config.config", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.config.config")?;
    Ok(())
}
