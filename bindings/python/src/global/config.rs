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

use binlex::Config as InnerConfig;
use pyo3::prelude::*;
use std::sync::{Arc, Mutex};

#[pyclass]
pub struct ConfigChromosomes {
    inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigChromosomes {
    #[getter]
    pub fn get_hashing(&self) -> ConfigChromosomesHashing {
        ConfigChromosomesHashing {
            inner: Arc::clone(&self.inner),
        }
    }
    #[getter]
    pub fn get_features(&self) -> ConfigChromosomesHeuristicsFeatures {
        ConfigChromosomesHeuristicsFeatures {
            inner: Arc::clone(&self.inner),
        }
    }

    #[getter]
    pub fn get_entropy(&self) -> ConfigChromosomesHeuristicsEntropy {
        ConfigChromosomesHeuristicsEntropy {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[pyclass]
pub struct ConfigChromosomesHashing {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigChromosomesHashing {
    #[getter]
    pub fn get_sha256(&self) -> ConfigChromosomesHashingSHA256 {
        ConfigChromosomesHashingSHA256 {
            inner: Arc::clone(&self.inner),
        }
    }

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
pub struct ConfigChromosomesHeuristicsEntropy {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigChromosomesHeuristicsEntropy {
    #[getter]
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.chromosomes.entropy.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.chromosomes.entropy.enabled = value;
    }
}

#[pyclass]
pub struct ConfigChromosomesHeuristicsFeatures {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigChromosomesHeuristicsFeatures {
    #[getter]
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.chromosomes.features.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.chromosomes.features.enabled = value;
    }
}

#[pyclass]
pub struct ConfigChromosomesHashingSHA256 {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigChromosomesHashingSHA256 {
    #[getter]
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.chromosomes.hashing.sha256.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.chromosomes.hashing.sha256.enabled = value;
    }
}

#[pyclass]
pub struct ConfigChromosomesHashingTLSH {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigChromosomesHashingTLSH {
    #[getter]
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.chromosomes.hashing.tlsh.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.chromosomes.hashing.tlsh.enabled = value;
    }

    #[getter]
    pub fn get_minimum_byte_size(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.chromosomes.hashing.tlsh.minimum_byte_size
    }

    #[setter]
    pub fn set_minimum_byte_size(&mut self, value: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.chromosomes.hashing.tlsh.minimum_byte_size = value;
    }
}

#[pyclass]
pub struct ConfigChromosomesHashingMinhash {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigChromosomesHashingMinhash {
    #[getter]
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.chromosomes.hashing.minhash.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.chromosomes.hashing.minhash.enabled = value;
    }

    #[getter]
    pub fn get_number_of_hashes(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.chromosomes.hashing.minhash.number_of_hashes
    }

    #[setter]
    pub fn set_number_of_hashes(&mut self, value: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.chromosomes.hashing.minhash.number_of_hashes = value;
    }

    #[getter]
    pub fn get_shingle_size(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.chromosomes.hashing.minhash.shingle_size
    }

    #[setter]
    pub fn set_shingle_size(&mut self, value: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.chromosomes.hashing.minhash.shingle_size = value;
    }

    #[getter]
    pub fn get_maximum_byte_size_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.chromosomes.hashing.minhash.maximum_byte_size_enabled
    }

    #[setter]
    pub fn set_maximum_byte_size_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.chromosomes.hashing.minhash.maximum_byte_size_enabled = value;
    }

    #[getter]
    pub fn get_maximum_byte_size(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.chromosomes.hashing.minhash.maximum_byte_size
    }

    #[setter]
    pub fn set_maximum_byte_size(&mut self, value: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.chromosomes.hashing.minhash.maximum_byte_size = value;
    }
    #[getter]
    pub fn get_seed(&self) -> u64 {
        let inner = self.inner.lock().unwrap();
        inner.chromosomes.hashing.minhash.seed
    }

    #[setter]
    pub fn set_seed(&mut self, value: u64) {
        let mut inner = self.inner.lock().unwrap();
        inner.chromosomes.hashing.minhash.seed = value;
    }
}

// stop

#[pyclass]
pub struct ConfigFunctions {
    inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigFunctions {
    #[getter]
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.functions.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.functions.enabled = value;
    }

    #[getter]
    pub fn get_hashing(&self) -> ConfigFunctionsHashing {
        ConfigFunctionsHashing {
            inner: Arc::clone(&self.inner),
        }
    }

    #[getter]
    pub fn get_entropy(&self) -> ConfigFunctionsHeuristicsEntropy {
        ConfigFunctionsHeuristicsEntropy {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[pyclass]
pub struct ConfigFunctionsHashing {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigFunctionsHashing {
    #[getter]
    pub fn get_sha256(&self) -> ConfigFunctionsHashingSHA256 {
        ConfigFunctionsHashingSHA256 {
            inner: Arc::clone(&self.inner),
        }
    }

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
}

#[pyclass]
pub struct ConfigFunctionsHeuristicsEntropy {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigFunctionsHeuristicsEntropy {
    #[getter]
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.functions.entropy.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.functions.entropy.enabled = value;
    }
}

#[pyclass]
pub struct ConfigFunctionsHashingSHA256 {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigFunctionsHashingSHA256 {
    #[getter]
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.functions.hashing.sha256.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.functions.hashing.sha256.enabled = value;
    }
}

#[pyclass]
pub struct ConfigFunctionsHashingTLSH {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigFunctionsHashingTLSH {
    #[getter]
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.functions.hashing.tlsh.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.functions.hashing.tlsh.enabled = value;
    }

    #[getter]
    pub fn get_minimum_byte_size(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.functions.hashing.tlsh.minimum_byte_size
    }

    #[setter]
    pub fn set_minimum_byte_size(&mut self, value: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.functions.hashing.tlsh.minimum_byte_size = value;
    }
}

#[pyclass]
pub struct ConfigFunctionsHashingMinhash {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigFunctionsHashingMinhash {
    #[getter]
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.functions.hashing.minhash.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.functions.hashing.minhash.enabled = value;
    }

    #[getter]
    pub fn get_number_of_hashes(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.functions.hashing.minhash.number_of_hashes
    }

    #[setter]
    pub fn set_number_of_hashes(&mut self, value: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.functions.hashing.minhash.number_of_hashes = value;
    }

    #[getter]
    pub fn get_shingle_size(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.functions.hashing.minhash.shingle_size
    }

    #[setter]
    pub fn set_shingle_size(&mut self, value: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.functions.hashing.minhash.shingle_size = value;
    }

    #[getter]
    pub fn get_maximum_byte_size_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.functions.hashing.minhash.maximum_byte_size_enabled
    }

    #[setter]
    pub fn set_maximum_byte_size_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.functions.hashing.minhash.maximum_byte_size_enabled = value;
    }

    #[getter]
    pub fn get_maximum_byte_size(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.functions.hashing.minhash.maximum_byte_size
    }

    #[setter]
    pub fn set_maximum_byte_size(&mut self, value: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.functions.hashing.minhash.maximum_byte_size = value;
    }
    #[getter]
    pub fn get_seed(&self) -> u64 {
        let inner = self.inner.lock().unwrap();
        inner.functions.hashing.minhash.seed
    }

    #[setter]
    pub fn set_seed(&mut self, value: u64) {
        let mut inner = self.inner.lock().unwrap();
        inner.functions.hashing.minhash.seed = value;
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
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.blocks.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.blocks.enabled = value;
    }

    #[getter]
    pub fn get_hashing(&self) -> ConfigBlocksHashing {
        ConfigBlocksHashing {
            inner: Arc::clone(&self.inner),
        }
    }

    #[getter]
    pub fn get_entropy(&self) -> ConfigBlocksHeuristicsEntropy {
        ConfigBlocksHeuristicsEntropy {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[pyclass]
pub struct ConfigInstructions {
    inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigInstructions {
    #[getter]
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.instructions.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.instructions.enabled = value;
    }
}

#[pyclass]
pub struct ConfigBlocksHashing {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigBlocksHashing {
    #[getter]
    pub fn get_sha256(&self) -> ConfigBlocksHashingSHA256 {
        ConfigBlocksHashingSHA256 {
            inner: Arc::clone(&self.inner),
        }
    }

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
pub struct ConfigBlocksHeuristicsEntropy {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigBlocksHeuristicsEntropy {
    #[getter]
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.blocks.entropy.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.blocks.entropy.enabled = value;
    }
}

#[pyclass]
pub struct ConfigBlocksHashingSHA256 {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigBlocksHashingSHA256 {
    #[getter]
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.blocks.hashing.sha256.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.blocks.hashing.sha256.enabled = value;
    }
}

#[pyclass]
pub struct ConfigBlocksHashingTLSH {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigBlocksHashingTLSH {
    #[getter]
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.blocks.hashing.tlsh.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.blocks.hashing.tlsh.enabled = value;
    }

    #[getter]
    pub fn get_minimum_byte_size(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.blocks.hashing.tlsh.minimum_byte_size
    }

    #[setter]
    pub fn set_minimum_byte_size(&mut self, value: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.blocks.hashing.tlsh.minimum_byte_size = value;
    }
}

#[pyclass]
pub struct ConfigBlocksHashingMinhash {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigBlocksHashingMinhash {
    #[getter]
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.blocks.hashing.minhash.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.blocks.hashing.minhash.enabled = value;
    }

    #[getter]
    pub fn get_number_of_hashes(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.blocks.hashing.minhash.number_of_hashes
    }

    #[setter]
    pub fn set_number_of_hashes(&mut self, value: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.blocks.hashing.minhash.number_of_hashes = value;
    }

    #[getter]
    pub fn get_shingle_size(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.blocks.hashing.minhash.shingle_size
    }

    #[setter]
    pub fn set_shingle_size(&mut self, value: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.blocks.hashing.minhash.shingle_size = value;
    }

    #[getter]
    pub fn get_maximum_byte_size_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.blocks.hashing.minhash.maximum_byte_size_enabled
    }

    #[setter]
    pub fn set_maximum_byte_size_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.blocks.hashing.minhash.maximum_byte_size_enabled = value;
    }

    #[getter]
    pub fn get_maximum_byte_size(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.blocks.hashing.minhash.maximum_byte_size
    }

    #[setter]
    pub fn set_maximum_byte_size(&mut self, value: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.blocks.hashing.minhash.maximum_byte_size = value;
    }

    #[getter]
    pub fn get_seed(&self) -> u64 {
        let inner = self.inner.lock().unwrap();
        inner.blocks.hashing.minhash.seed
    }

    #[setter]
    pub fn set_seed(&mut self, value: u64) {
        let mut inner = self.inner.lock().unwrap();
        inner.blocks.hashing.minhash.seed = value;
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
    pub fn get_hashing(&self) -> ConfigFormatsFileHashing {
        ConfigFormatsFileHashing {
            inner: Arc::clone(&self.inner),
        }
    }
    #[getter]
    pub fn get_entropy(&self) -> ConfigFormatsFileHeuristicsEntropy {
        ConfigFormatsFileHeuristicsEntropy {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[pyclass]
pub struct ConfigFormatsFileHashing {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigFormatsFileHashing {
    #[getter]
    pub fn get_sha256(&self) -> ConfigFormatsFileHashingSHA256 {
        ConfigFormatsFileHashingSHA256 {
            inner: Arc::clone(&self.inner),
        }
    }

    #[getter]
    pub fn get_tlsh(&self) -> ConfigFormatsFileHashingTLSH {
        ConfigFormatsFileHashingTLSH {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[pyclass]
pub struct ConfigFormatsFileHeuristicsEntropy {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigFormatsFileHeuristicsEntropy {
    #[getter]
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.formats.file.entropy.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.formats.file.entropy.enabled = value;
    }
}

#[pyclass]
pub struct ConfigFormatsFileHashingSHA256 {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigFormatsFileHashingSHA256 {
    #[getter]
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.formats.file.hashing.sha256.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.formats.file.hashing.sha256.enabled = value;
    }
}

#[pyclass]
pub struct ConfigFormatsFileHashingTLSH {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigFormatsFileHashingTLSH {
    #[getter]
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.formats.file.hashing.tlsh.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.formats.file.hashing.tlsh.enabled = value;
    }

    #[getter]
    pub fn get_minimum_byte_size(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.formats.file.hashing.tlsh.minimum_byte_size
    }

    #[setter]
    pub fn set_minimum_byte_size(&mut self, value: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.formats.file.hashing.tlsh.minimum_byte_size = value;
    }
}

/// Top-level mutable configuration object for binlex analysis behavior.
#[pyclass]
pub struct Config {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl Config {
    #[new]
    /// Create a configuration object initialized with built-in defaults.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(InnerConfig::new())),
        }
    }

    #[getter]
    /// Return the general configuration group.
    pub fn get_general(&self) -> PyResult<ConfigGeneral> {
        Ok(ConfigGeneral {
            inner: Arc::clone(&self.inner),
        })
    }

    #[getter]
    /// Return the processor execution configuration group.
    pub fn get_processors(&self) -> PyResult<ConfigProcessors> {
        Ok(ConfigProcessors {
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
    /// Return the block analysis configuration group.
    pub fn get_blocks(&self) -> PyResult<ConfigBlocks> {
        Ok(ConfigBlocks {
            inner: Arc::clone(&self.inner),
        })
    }

    #[getter]
    /// Return the instruction analysis configuration group.
    pub fn get_instructions(&self) -> PyResult<ConfigInstructions> {
        Ok(ConfigInstructions {
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

    #[pyo3(text_signature = "($self)")]
    /// Enable the minimal-analysis preset.
    pub fn enable_minimal(&mut self) {
        self.inner.lock().unwrap().enable_minimal();
    }

    #[pyo3(text_signature = "($self)")]
    /// Disable configured hashing features where supported.
    pub fn disable_hashing(&mut self) {
        self.inner.lock().unwrap().disable_hashing();
    }

    #[pyo3(text_signature = "($self)")]
    /// Disable heuristic features where supported.
    pub fn disable_heuristics(&mut self) {
        self.inner.lock().unwrap().disable_heuristics();
    }

    #[pyo3(text_signature = "($self)")]
    /// Disable chromosome-specific heuristics.
    pub fn disable_chromosome_heuristics(&mut self) {
        self.inner.lock().unwrap().disable_chromosome_heuristics();
    }

    #[pyo3(text_signature = "($self)")]
    /// Disable chromosome-specific hashing.
    pub fn disable_chromosome_hashing(&mut self) {
        self.inner.lock().unwrap().disable_chromosome_hashing();
    }

    #[pyo3(text_signature = "($self)")]
    /// Disable block hashing features.
    pub fn disable_block_hashing(&mut self) {
        self.inner.lock().unwrap().disable_block_hashing();
    }

    #[pyo3(text_signature = "($self)")]
    /// Disable function hashing features.
    pub fn disable_function_hashing(&mut self) {
        self.inner.lock().unwrap().disable_function_hashing();
    }

    #[pyo3(text_signature = "($self)")]
    /// Disable function heuristics.
    pub fn disable_function_heuristics(&mut self) {
        self.inner.lock().unwrap().disable_function_heuristics();
    }

    #[pyo3(text_signature = "($self)")]
    /// Disable block heuristics.
    pub fn disable_block_heuristics(&mut self) {
        self.inner.lock().unwrap().disable_block_heuristics();
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

impl Default for Config {
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

#[pyclass]
pub struct ConfigGeneral {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigGeneral {
    #[getter]
    pub fn get_threads(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.general.threads
    }

    #[setter]
    pub fn set_threads(&mut self, value: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.general.threads = value;
    }

    #[getter]
    pub fn get_minimal(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.general.minimal
    }

    #[setter]
    pub fn set_minimal(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.general.minimal = value;
    }

    #[getter]
    pub fn get_debug(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.general.debug
    }

    #[setter]
    pub fn set_debug(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.general.debug = value;
    }
}

/// Access settings that control processor orchestration and worker behavior.
#[pyclass]
pub struct ConfigProcessors {
    pub inner: Arc<Mutex<InnerConfig>>,
}

/// Access settings for a single named processor backend.
#[pyclass]
pub struct ConfigProcessor {
    pub inner: Arc<Mutex<InnerConfig>>,
    pub name: String,
}

/// Access per-target enablement for processor-produced objects.
#[pyclass]
pub struct ConfigProcessorTarget {
    pub inner: Arc<Mutex<InnerConfig>>,
    pub processor_name: String,
    pub kind: &'static str,
}

#[pymethods]
impl ConfigProcessorTarget {
    #[getter]
    /// Return whether this processor target type is enabled.
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner
            .processors
            .processor(&self.processor_name)
            .is_some_and(|processor| match self.kind {
                "instructions" => processor.instructions.enabled,
                "blocks" => processor.blocks.enabled,
                "functions" => processor.functions.enabled,
                _ => false,
            })
    }

    #[setter]
    /// Enable or disable this processor target type.
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(processor) = inner.processors.ensure_processor(&self.processor_name) {
            match self.kind {
                "instructions" => processor.instructions.enabled = value,
                "blocks" => processor.blocks.enabled = value,
                "functions" => processor.functions.enabled = value,
                _ => {}
            }
        }
    }
}

#[pymethods]
impl ConfigProcessor {
    #[getter]
    /// Return whether this processor backend is enabled.
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner
            .processors
            .processor(&self.name)
            .is_some_and(|processor| processor.enabled)
    }

    #[setter]
    /// Enable or disable this processor backend.
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(processor) = inner.processors.ensure_processor(&self.name) {
            processor.enabled = value;
        }
    }

    #[getter]
    /// Return settings for instruction outputs produced by this processor.
    pub fn get_instructions(&self) -> ConfigProcessorTarget {
        ConfigProcessorTarget {
            inner: Arc::clone(&self.inner),
            processor_name: self.name.clone(),
            kind: "instructions",
        }
    }

    #[getter]
    /// Return settings for block outputs produced by this processor.
    pub fn get_blocks(&self) -> ConfigProcessorTarget {
        ConfigProcessorTarget {
            inner: Arc::clone(&self.inner),
            processor_name: self.name.clone(),
            kind: "blocks",
        }
    }

    #[getter]
    /// Return settings for function outputs produced by this processor.
    pub fn get_functions(&self) -> ConfigProcessorTarget {
        ConfigProcessorTarget {
            inner: Arc::clone(&self.inner),
            processor_name: self.name.clone(),
            kind: "functions",
        }
    }
}

#[pymethods]
impl ConfigProcessors {
    /// Return a processor configuration view by name.
    pub fn processor(&self, name: String) -> ConfigProcessor {
        ConfigProcessor {
            inner: Arc::clone(&self.inner),
            name,
        }
    }

    #[getter]
    /// Return the built-in VEX processor configuration.
    pub fn get_vex(&self) -> ConfigProcessor {
        ConfigProcessor {
            inner: Arc::clone(&self.inner),
            name: "vex".to_string(),
        }
    }

    #[getter]
    /// Return whether processor orchestration is enabled.
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.processors.enabled
    }

    #[setter]
    /// Enable or disable processor orchestration.
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.processors.enabled = value;
    }

    #[getter]
    pub fn get_path(&self) -> Option<String> {
        let inner = self.inner.lock().unwrap();
        inner.processors.path.clone()
    }

    #[setter]
    pub fn set_path(&mut self, value: Option<String>) {
        let mut inner = self.inner.lock().unwrap();
        inner.processors.path = value;
    }

    #[getter]
    pub fn get_processes(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.processors.processes
    }

    #[setter]
    pub fn set_processes(&mut self, value: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.processors.processes = value.max(1);
    }

    #[getter]
    pub fn get_compression(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.processors.compression
    }

    #[setter]
    pub fn set_compression(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.processors.compression = value;
    }

    #[getter]
    pub fn get_restart_on_crash(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.processors.restart_on_crash
    }

    #[setter]
    pub fn set_restart_on_crash(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.processors.restart_on_crash = value;
    }

    #[getter]
    pub fn get_max_payload_bytes(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.processors.max_payload_bytes
    }

    #[setter]
    pub fn set_max_payload_bytes(&mut self, value: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.processors.max_payload_bytes = value;
    }

    #[getter]
    pub fn get_idle_timeout_ms(&self) -> u64 {
        let inner = self.inner.lock().unwrap();
        inner.processors.idle_timeout_ms
    }

    #[setter]
    pub fn set_idle_timeout_ms(&mut self, value: u64) {
        let mut inner = self.inner.lock().unwrap();
        inner.processors.idle_timeout_ms = value;
    }

    #[getter]
    pub fn get_max_queue_depth(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.processors.max_queue_depth
    }

    #[setter]
    pub fn set_max_queue_depth(&mut self, value: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.processors.max_queue_depth = value.max(1);
    }
}

#[pymodule]
#[pyo3(name = "config")]
pub fn config_init(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Config>()?;
    m.add_class::<ConfigProcessorTarget>()?;
    m.add_class::<ConfigProcessors>()?;
    m.add_class::<ConfigProcessor>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex._global.config", m)?;
    m.setattr("__name__", "binlex_bindings.binlex._global.config")?;
    Ok(())
}
