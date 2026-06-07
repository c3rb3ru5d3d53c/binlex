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
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use std::sync::{Arc, Mutex};

#[pyclass]
pub struct ConfigChromosomes {
    inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigChromosomes {
    #[getter]
    pub fn get_tlsh(&self) -> ConfigChromosomesHashingTLSH {
        ConfigChromosomesHashingTLSH {
            inner: Arc::clone(&self.inner),
        }
    }

    #[getter]
    pub fn get_minhash(&self) -> ConfigChromosomesHashingMinhash {
        ConfigChromosomesHashingMinhash {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[pyclass]
pub struct ConfigChromosomesHashingTLSH {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigChromosomesHashingTLSH {
    #[getter]
    pub fn get_minimum_byte_size(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.chromosomes.tlsh.minimum_byte_size
    }

    #[setter]
    pub fn set_minimum_byte_size(&mut self, value: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.chromosomes.tlsh.minimum_byte_size = value;
    }
}

#[pyclass]
pub struct ConfigChromosomesHashingMinhash {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigChromosomesHashingMinhash {
    #[getter]
    pub fn get_number_of_hashes(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.chromosomes.minhash.number_of_hashes
    }

    #[setter]
    pub fn set_number_of_hashes(&mut self, value: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.chromosomes.minhash.number_of_hashes = value;
    }

    #[getter]
    pub fn get_shingle_size(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.chromosomes.minhash.shingle_size
    }

    #[setter]
    pub fn set_shingle_size(&mut self, value: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.chromosomes.minhash.shingle_size = value;
    }

    #[getter]
    pub fn get_maximum_byte_size_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.chromosomes.minhash.maximum_byte_size_enabled
    }

    #[setter]
    pub fn set_maximum_byte_size_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.chromosomes.minhash.maximum_byte_size_enabled = value;
    }

    #[getter]
    pub fn get_maximum_byte_size(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.chromosomes.minhash.maximum_byte_size
    }

    #[setter]
    pub fn set_maximum_byte_size(&mut self, value: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.chromosomes.minhash.maximum_byte_size = value;
    }
    #[getter]
    pub fn get_seed(&self) -> u64 {
        let inner = self.inner.lock().unwrap();
        inner.chromosomes.minhash.seed
    }

    #[setter]
    pub fn set_seed(&mut self, value: u64) {
        let mut inner = self.inner.lock().unwrap();
        inner.chromosomes.minhash.seed = value;
    }
}

#[pyclass]
pub struct ConfigFunctions {
    inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigFunctions {
    #[getter]
    pub fn get_tlsh(&self) -> ConfigFunctionsHashingTLSH {
        ConfigFunctionsHashingTLSH {
            inner: Arc::clone(&self.inner),
        }
    }

    #[getter]
    pub fn get_minhash(&self) -> ConfigFunctionsHashingMinhash {
        ConfigFunctionsHashingMinhash {
            inner: Arc::clone(&self.inner),
        }
    }

    #[getter]
    pub fn get_markov(&self) -> ConfigFunctionsMarkov {
        ConfigFunctionsMarkov {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[pyclass]
pub struct ConfigFunctionsMarkov {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigFunctionsMarkov {
    #[getter]
    pub fn get_damping(&self) -> f64 {
        let inner = self.inner.lock().unwrap();
        inner.functions.markov.damping
    }

    #[setter]
    pub fn set_damping(&mut self, value: f64) {
        let mut inner = self.inner.lock().unwrap();
        inner.functions.markov.damping = value;
    }

    #[getter]
    pub fn get_tolerance(&self) -> f64 {
        let inner = self.inner.lock().unwrap();
        inner.functions.markov.tolerance
    }

    #[setter]
    pub fn set_tolerance(&mut self, value: f64) {
        let mut inner = self.inner.lock().unwrap();
        inner.functions.markov.tolerance = value;
    }

    #[getter]
    pub fn get_max_iterations(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.functions.markov.max_iterations
    }

    #[setter]
    pub fn set_max_iterations(&mut self, value: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.functions.markov.max_iterations = value;
    }
}

#[pyclass]
pub struct ConfigFunctionsHashingTLSH {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigFunctionsHashingTLSH {
    #[getter]
    pub fn get_minimum_byte_size(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.functions.tlsh.minimum_byte_size
    }

    #[setter]
    pub fn set_minimum_byte_size(&mut self, value: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.functions.tlsh.minimum_byte_size = value;
    }
}

#[pyclass]
pub struct ConfigFunctionsHashingMinhash {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigFunctionsHashingMinhash {
    #[getter]
    pub fn get_number_of_hashes(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.functions.minhash.number_of_hashes
    }

    #[setter]
    pub fn set_number_of_hashes(&mut self, value: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.functions.minhash.number_of_hashes = value;
    }

    #[getter]
    pub fn get_shingle_size(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.functions.minhash.shingle_size
    }

    #[setter]
    pub fn set_shingle_size(&mut self, value: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.functions.minhash.shingle_size = value;
    }

    #[getter]
    pub fn get_maximum_byte_size_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.functions.minhash.maximum_byte_size_enabled
    }

    #[setter]
    pub fn set_maximum_byte_size_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.functions.minhash.maximum_byte_size_enabled = value;
    }

    #[getter]
    pub fn get_maximum_byte_size(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.functions.minhash.maximum_byte_size
    }

    #[setter]
    pub fn set_maximum_byte_size(&mut self, value: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.functions.minhash.maximum_byte_size = value;
    }
    #[getter]
    pub fn get_seed(&self) -> u64 {
        let inner = self.inner.lock().unwrap();
        inner.functions.minhash.seed
    }

    #[setter]
    pub fn set_seed(&mut self, value: u64) {
        let mut inner = self.inner.lock().unwrap();
        inner.functions.minhash.seed = value;
    }
}

// stop

#[pyclass]
pub struct ConfigBlocks {
    inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigBlocks {
    #[getter]
    pub fn get_tlsh(&self) -> ConfigBlocksHashingTLSH {
        ConfigBlocksHashingTLSH {
            inner: Arc::clone(&self.inner),
        }
    }

    #[getter]
    pub fn get_minhash(&self) -> ConfigBlocksHashingMinhash {
        ConfigBlocksHashingMinhash {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[pyclass]
pub struct ConfigBlocksHashingTLSH {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigBlocksHashingTLSH {
    #[getter]
    pub fn get_minimum_byte_size(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.blocks.tlsh.minimum_byte_size
    }

    #[setter]
    pub fn set_minimum_byte_size(&mut self, value: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.blocks.tlsh.minimum_byte_size = value;
    }
}

#[pyclass]
pub struct ConfigBlocksHashingMinhash {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigBlocksHashingMinhash {
    #[getter]
    pub fn get_number_of_hashes(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.blocks.minhash.number_of_hashes
    }

    #[setter]
    pub fn set_number_of_hashes(&mut self, value: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.blocks.minhash.number_of_hashes = value;
    }

    #[getter]
    pub fn get_shingle_size(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.blocks.minhash.shingle_size
    }

    #[setter]
    pub fn set_shingle_size(&mut self, value: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.blocks.minhash.shingle_size = value;
    }

    #[getter]
    pub fn get_maximum_byte_size_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.blocks.minhash.maximum_byte_size_enabled
    }

    #[setter]
    pub fn set_maximum_byte_size_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.blocks.minhash.maximum_byte_size_enabled = value;
    }

    #[getter]
    pub fn get_maximum_byte_size(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.blocks.minhash.maximum_byte_size
    }

    #[setter]
    pub fn set_maximum_byte_size(&mut self, value: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.blocks.minhash.maximum_byte_size = value;
    }

    #[getter]
    pub fn get_seed(&self) -> u64 {
        let inner = self.inner.lock().unwrap();
        inner.blocks.minhash.seed
    }

    #[setter]
    pub fn set_seed(&mut self, value: u64) {
        let mut inner = self.inner.lock().unwrap();
        inner.blocks.minhash.seed = value;
    }
}

/// stop

#[pyclass]
pub struct ConfigFormats {
    inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigFormats {
    #[getter]
    pub fn get_file(&self) -> ConfigFormatsFile {
        ConfigFormatsFile {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[pyclass]
pub struct ConfigFormatsFile {
    inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigFormatsFile {
    #[getter]
    pub fn get_tlsh(&self) -> ConfigFormatsFileHashingTLSH {
        ConfigFormatsFileHashingTLSH {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[pyclass]
pub struct ConfigFormatsFileHashingTLSH {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigFormatsFileHashingTLSH {
    #[getter]
    pub fn get_minimum_byte_size(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.formats.file.tlsh.minimum_byte_size
    }

    #[setter]
    pub fn set_minimum_byte_size(&mut self, value: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.formats.file.tlsh.minimum_byte_size = value;
    }
}

#[pyclass]
pub struct ConfigImaging {
    inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigImaging {
    #[getter]
    pub fn get_tlsh(&self) -> ConfigImagingTLSH {
        ConfigImagingTLSH {
            inner: Arc::clone(&self.inner),
        }
    }

    #[getter]
    pub fn get_minhash(&self) -> ConfigImagingMinhash {
        ConfigImagingMinhash {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[pyclass]
pub struct ConfigImagingTLSH {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigImagingTLSH {
    #[getter]
    pub fn get_minimum_byte_size(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.imaging.tlsh.minimum_byte_size
    }

    #[setter]
    pub fn set_minimum_byte_size(&mut self, value: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.imaging.tlsh.minimum_byte_size = value;
    }
}

#[pyclass]
pub struct ConfigImagingMinhash {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigImagingMinhash {
    #[getter]
    pub fn get_number_of_hashes(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.imaging.minhash.number_of_hashes
    }

    #[setter]
    pub fn set_number_of_hashes(&mut self, value: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.imaging.minhash.number_of_hashes = value;
    }

    #[getter]
    pub fn get_shingle_size(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.imaging.minhash.shingle_size
    }

    #[setter]
    pub fn set_shingle_size(&mut self, value: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.imaging.minhash.shingle_size = value;
    }

    #[getter]
    pub fn get_maximum_byte_size_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.imaging.minhash.maximum_byte_size_enabled
    }

    #[setter]
    pub fn set_maximum_byte_size_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.imaging.minhash.maximum_byte_size_enabled = value;
    }

    #[getter]
    pub fn get_maximum_byte_size(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.imaging.minhash.maximum_byte_size
    }

    #[setter]
    pub fn set_maximum_byte_size(&mut self, value: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.imaging.minhash.maximum_byte_size = value;
    }

    #[getter]
    pub fn get_seed(&self) -> u64 {
        let inner = self.inner.lock().unwrap();
        inner.imaging.minhash.seed
    }

    #[setter]
    pub fn set_seed(&mut self, value: u64) {
        let mut inner = self.inner.lock().unwrap();
        inner.imaging.minhash.seed = value;
    }
}

#[pyclass]
pub struct ConfigIrs {
    pub inner: Arc<Mutex<InnerConfig>>,
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
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigIrsLLVM {
    #[getter]
    pub fn get_module_name(&self) -> String {
        let inner = self.inner.lock().unwrap();
        inner.irs.llvm.module_name.clone()
    }

    #[setter]
    pub fn set_module_name(&mut self, value: String) {
        let mut inner = self.inner.lock().unwrap();
        inner.irs.llvm.module_name = value;
    }

    #[getter]
    pub fn get_verify(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.irs.llvm.verify
    }

    #[setter]
    pub fn set_verify(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.irs.llvm.verify = value;
    }

    #[getter]
    pub fn get_mode(&self) -> String {
        let inner = self.inner.lock().unwrap();
        match inner.irs.llvm.mode {
            binlex::irs::llvm::Mode::Reconstruct => "reconstruct",
            binlex::irs::llvm::Mode::Intrinsic => "intrinsic",
            binlex::irs::llvm::Mode::Lir => "lir",
        }
        .to_string()
    }

    #[setter]
    pub fn set_mode(&mut self, value: String) -> PyResult<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.irs.llvm.mode = match value.as_str() {
            "reconstruct" => binlex::irs::llvm::Mode::Reconstruct,
            "intrinsic" => binlex::irs::llvm::Mode::Intrinsic,
            "lir" => binlex::irs::llvm::Mode::Lir,
            _ => {
                return Err(PyRuntimeError::new_err(format!(
                    "invalid llvm mode: {value}"
                )));
            }
        };
        Ok(())
    }
}

#[pyclass]
pub struct ConfigEmbeddings {
    pub inner: Arc<Mutex<InnerConfig>>,
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
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigEmbeddingsLLVM {
    #[getter]
    pub fn get_dimensions(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.embeddings.llvm.dimensions
    }

    #[setter]
    pub fn set_dimensions(&mut self, value: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.embeddings.llvm.dimensions = value.max(1);
    }

    #[getter]
    pub fn get_device(&self) -> String {
        let inner = self.inner.lock().unwrap();
        inner.embeddings.llvm.device.clone()
    }

    #[setter]
    pub fn set_device(&mut self, value: String) {
        let mut inner = self.inner.lock().unwrap();
        inner.embeddings.llvm.device = value;
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

    #[getter]
    /// Return the configured analysis thread count. A value of 0 means automatic.
    pub fn get_threads(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.threads
    }

    #[setter]
    pub fn set_threads(&mut self, value: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.threads = value;
    }

    #[getter]
    /// Return whether debug logging is enabled.
    pub fn get_debug(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.debug
    }

    #[setter]
    pub fn set_debug(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.debug = value;
    }

    #[getter]
    /// Return the embeddings configuration group.
    pub fn get_embeddings(&self) -> PyResult<ConfigEmbeddings> {
        Ok(ConfigEmbeddings {
            inner: Arc::clone(&self.inner),
        })
    }

    #[getter]
    /// Return the format parsing configuration group.
    pub fn get_formats(&self) -> PyResult<ConfigFormats> {
        Ok(ConfigFormats {
            inner: Arc::clone(&self.inner),
        })
    }

    #[getter]
    /// Return the imaging configuration group.
    pub fn get_imaging(&self) -> PyResult<ConfigImaging> {
        Ok(ConfigImaging {
            inner: Arc::clone(&self.inner),
        })
    }

    #[getter]
    /// Return the block analysis configuration group.
    pub fn get_blocks(&self) -> PyResult<ConfigBlocks> {
        Ok(ConfigBlocks {
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
    /// Return the chromosome analysis configuration group.
    pub fn get_chromosomes(&self) -> PyResult<ConfigChromosomes> {
        Ok(ConfigChromosomes {
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
    pub inner: Arc<Mutex<InnerConfig>>,
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
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigDisassemblerSweep {
    #[getter]
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.disassembler.sweep.enabled
    }
    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.disassembler.sweep.enabled = value;
    }
}

#[pyclass]
pub struct ConfigMmap {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigMmap {
    #[getter]
    pub fn get_directory(&self) -> String {
        let inner = self.inner.lock().unwrap();
        inner.mmap.directory.clone()
    }

    #[setter]
    pub fn set_directory(&mut self, value: String) {
        let mut inner = self.inner.lock().unwrap();
        inner.mmap.directory = value;
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
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigMmapCache {
    #[getter]
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.mmap.cache.enabled
    }
    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.mmap.cache.enabled = value;
    }
}

pub fn register_config(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Configuration>()?;
    m.add_class::<ConfigIrs>()?;
    m.add_class::<ConfigIrsLLVM>()?;
    m.add_class::<ConfigEmbeddings>()?;
    m.add_class::<ConfigEmbeddingsLLVM>()?;
    m.add_class::<ConfigFunctions>()?;
    m.add_class::<ConfigBlocks>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.config.config", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.config.config")?;
    Ok(())
}
