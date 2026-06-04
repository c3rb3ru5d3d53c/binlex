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
    pub fn get_mask(&self) -> ConfigChromosomesMask {
        ConfigChromosomesMask {
            inner: Arc::clone(&self.inner),
        }
    }

    #[getter]
    pub fn get_masked(&self) -> ConfigChromosomesMasked {
        ConfigChromosomesMasked {
            inner: Arc::clone(&self.inner),
        }
    }

    #[getter]
    pub fn get_sha256(&self) -> ConfigChromosomesHashingSHA256 {
        ConfigChromosomesHashingSHA256 {
            inner: Arc::clone(&self.inner),
        }
    }

    #[getter]
    pub fn get_ssdeep(&self) -> ConfigChromosomesHashingSSDeep {
        ConfigChromosomesHashingSSDeep {
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

    #[getter]
    pub fn get_vector(&self) -> ConfigChromosomesHeuristicsVector {
        ConfigChromosomesHeuristicsVector {
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
    pub fn get_ssdeep(&self) -> ConfigChromosomesHashingSSDeep {
        ConfigChromosomesHashingSSDeep {
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
pub struct ConfigChromosomesMask {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigChromosomesMask {
    #[getter]
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.chromosomes.mask.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.chromosomes.mask.enabled = value;
    }
}

#[pyclass]
pub struct ConfigChromosomesMasked {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigChromosomesMasked {
    #[getter]
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.chromosomes.masked.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.chromosomes.masked.enabled = value;
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
pub struct ConfigChromosomesHeuristicsVector {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigChromosomesHeuristicsVector {
    #[getter]
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.chromosomes.vector.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.chromosomes.vector.enabled = value;
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
        inner.chromosomes.sha256.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.chromosomes.sha256.enabled = value;
    }
}

#[pyclass]
pub struct ConfigChromosomesHashingSSDeep {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigChromosomesHashingSSDeep {
    #[getter]
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.chromosomes.ssdeep.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.chromosomes.ssdeep.enabled = value;
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
        inner.chromosomes.tlsh.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.chromosomes.tlsh.enabled = value;
    }

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
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.chromosomes.minhash.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.chromosomes.minhash.enabled = value;
    }

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

// stop

#[pyclass]
pub struct ConfigEntityLifters {
    pub inner: Arc<Mutex<InnerConfig>>,
    pub entity: &'static str,
}

#[pymethods]
impl ConfigEntityLifters {
    #[getter]
    pub fn get_llvm(&self) -> ConfigEntityLifterLLVM {
        ConfigEntityLifterLLVM {
            inner: Arc::clone(&self.inner),
            entity: self.entity,
        }
    }

    #[getter]
    pub fn get_vex(&self) -> ConfigEntityLifterVex {
        ConfigEntityLifterVex {
            inner: Arc::clone(&self.inner),
            entity: self.entity,
        }
    }
}

#[pyclass]
pub struct ConfigEntityLifterLLVM {
    pub inner: Arc<Mutex<InnerConfig>>,
    pub entity: &'static str,
}

#[pymethods]
impl ConfigEntityLifterLLVM {
    #[getter]
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        match self.entity {
            "instructions" => inner.instructions.lifters.llvm.enabled,
            "blocks" => inner.blocks.lifters.llvm.enabled,
            "functions" => inner.functions.lifters.llvm.enabled,
            _ => false,
        }
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        match self.entity {
            "instructions" => inner.instructions.lifters.llvm.enabled = value,
            "blocks" => inner.blocks.lifters.llvm.enabled = value,
            "functions" => inner.functions.lifters.llvm.enabled = value,
            _ => {}
        }
    }
}

#[pyclass]
pub struct ConfigEntityLifterVex {
    pub inner: Arc<Mutex<InnerConfig>>,
    pub entity: &'static str,
}

#[pymethods]
impl ConfigEntityLifterVex {
    #[getter]
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        match self.entity {
            "instructions" => inner.instructions.lifters.vex.enabled,
            "blocks" => inner.blocks.lifters.vex.enabled,
            "functions" => inner.functions.lifters.vex.enabled,
            _ => false,
        }
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        match self.entity {
            "instructions" => inner.instructions.lifters.vex.enabled = value,
            "blocks" => inner.blocks.lifters.vex.enabled = value,
            "functions" => inner.functions.lifters.vex.enabled = value,
            _ => {}
        }
    }
}

#[pyclass]
pub struct ConfigEntityEmbeddings {
    pub inner: Arc<Mutex<InnerConfig>>,
    pub entity: &'static str,
}

#[pymethods]
impl ConfigEntityEmbeddings {
    #[getter]
    pub fn get_llvm(&self) -> ConfigEntityEmbeddingsLLVM {
        ConfigEntityEmbeddingsLLVM {
            inner: Arc::clone(&self.inner),
            entity: self.entity,
        }
    }
}

#[pyclass]
pub struct ConfigEntityEmbeddingsLLVM {
    pub inner: Arc<Mutex<InnerConfig>>,
    pub entity: &'static str,
}

#[pymethods]
impl ConfigEntityEmbeddingsLLVM {
    #[getter]
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        match self.entity {
            "instructions" => inner.instructions.embeddings.llvm.enabled,
            "blocks" => inner.blocks.embeddings.llvm.enabled,
            "functions" => inner.functions.embeddings.llvm.enabled,
            _ => false,
        }
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        match self.entity {
            "instructions" => inner.instructions.embeddings.llvm.enabled = value,
            "blocks" => inner.blocks.embeddings.llvm.enabled = value,
            "functions" => inner.functions.embeddings.llvm.enabled = value,
            _ => {}
        }
    }
}

#[pyclass]
pub struct ConfigFunctions {
    inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigFunctions {
    #[getter]
    pub fn get_sha256(&self) -> ConfigFunctionsHashingSHA256 {
        ConfigFunctionsHashingSHA256 {
            inner: Arc::clone(&self.inner),
        }
    }

    #[getter]
    pub fn get_ssdeep(&self) -> ConfigFunctionsHashingSSDeep {
        ConfigFunctionsHashingSSDeep {
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
    pub fn get_entropy(&self) -> ConfigFunctionsHeuristicsEntropy {
        ConfigFunctionsHeuristicsEntropy {
            inner: Arc::clone(&self.inner),
        }
    }

    #[getter]
    pub fn get_markov(&self) -> ConfigFunctionsMarkov {
        ConfigFunctionsMarkov {
            inner: Arc::clone(&self.inner),
        }
    }

    #[getter]
    pub fn get_lifters(&self) -> ConfigEntityLifters {
        ConfigEntityLifters {
            inner: Arc::clone(&self.inner),
            entity: "functions",
        }
    }

    #[getter]
    pub fn get_embeddings(&self) -> ConfigEntityEmbeddings {
        ConfigEntityEmbeddings {
            inner: Arc::clone(&self.inner),
            entity: "functions",
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
    pub fn get_ssdeep(&self) -> ConfigFunctionsHashingSSDeep {
        ConfigFunctionsHashingSSDeep {
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
pub struct ConfigFunctionsMarkov {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigFunctionsMarkov {
    #[getter]
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.functions.markov.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.functions.markov.enabled = value;
    }

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
pub struct ConfigFunctionsHashingSHA256 {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigFunctionsHashingSHA256 {
    #[getter]
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.functions.sha256.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.functions.sha256.enabled = value;
    }
}

#[pyclass]
pub struct ConfigFunctionsHashingSSDeep {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigFunctionsHashingSSDeep {
    #[getter]
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.functions.ssdeep.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.functions.ssdeep.enabled = value;
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
        inner.functions.tlsh.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.functions.tlsh.enabled = value;
    }

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
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.functions.minhash.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.functions.minhash.enabled = value;
    }

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
    pub fn get_sha256(&self) -> ConfigBlocksHashingSHA256 {
        ConfigBlocksHashingSHA256 {
            inner: Arc::clone(&self.inner),
        }
    }

    #[getter]
    pub fn get_ssdeep(&self) -> ConfigBlocksHashingSSDeep {
        ConfigBlocksHashingSSDeep {
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
    pub fn get_entropy(&self) -> ConfigBlocksHeuristicsEntropy {
        ConfigBlocksHeuristicsEntropy {
            inner: Arc::clone(&self.inner),
        }
    }

    #[getter]
    pub fn get_lifters(&self) -> ConfigEntityLifters {
        ConfigEntityLifters {
            inner: Arc::clone(&self.inner),
            entity: "blocks",
        }
    }

    #[getter]
    pub fn get_embeddings(&self) -> ConfigEntityEmbeddings {
        ConfigEntityEmbeddings {
            inner: Arc::clone(&self.inner),
            entity: "blocks",
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

    #[getter]
    pub fn get_lifters(&self) -> ConfigEntityLifters {
        ConfigEntityLifters {
            inner: Arc::clone(&self.inner),
            entity: "instructions",
        }
    }

    #[getter]
    pub fn get_embeddings(&self) -> ConfigEntityEmbeddings {
        ConfigEntityEmbeddings {
            inner: Arc::clone(&self.inner),
            entity: "instructions",
        }
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
    pub fn get_ssdeep(&self) -> ConfigBlocksHashingSSDeep {
        ConfigBlocksHashingSSDeep {
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
        inner.blocks.sha256.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.blocks.sha256.enabled = value;
    }
}

#[pyclass]
pub struct ConfigBlocksHashingSSDeep {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigBlocksHashingSSDeep {
    #[getter]
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.blocks.ssdeep.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.blocks.ssdeep.enabled = value;
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
        inner.blocks.tlsh.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.blocks.tlsh.enabled = value;
    }

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
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.blocks.minhash.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.blocks.minhash.enabled = value;
    }

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
    pub fn get_sha256(&self) -> ConfigFormatsFileHashingSHA256 {
        ConfigFormatsFileHashingSHA256 {
            inner: Arc::clone(&self.inner),
        }
    }

    #[getter]
    pub fn get_ssdeep(&self) -> ConfigFormatsFileHashingSSDeep {
        ConfigFormatsFileHashingSSDeep {
            inner: Arc::clone(&self.inner),
        }
    }

    #[getter]
    pub fn get_tlsh(&self) -> ConfigFormatsFileHashingTLSH {
        ConfigFormatsFileHashingTLSH {
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
    pub fn get_ssdeep(&self) -> ConfigFormatsFileHashingSSDeep {
        ConfigFormatsFileHashingSSDeep {
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
        inner.formats.file.sha256.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.formats.file.sha256.enabled = value;
    }
}

#[pyclass]
pub struct ConfigFormatsFileHashingSSDeep {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigFormatsFileHashingSSDeep {
    #[getter]
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.formats.file.ssdeep.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.formats.file.ssdeep.enabled = value;
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
        inner.formats.file.tlsh.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.formats.file.tlsh.enabled = value;
    }

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
pub struct ConfigLifters {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigLifters {
    #[getter]
    pub fn get_llvm(&self) -> ConfigLiftersLLVM {
        ConfigLiftersLLVM {
            inner: Arc::clone(&self.inner),
        }
    }

    #[getter]
    pub fn get_vex(&self) -> ConfigLiftersVex {
        ConfigLiftersVex {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[pyclass]
pub struct ConfigLiftersLLVM {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigLiftersLLVM {
    #[getter]
    pub fn get_module_name(&self) -> String {
        let inner = self.inner.lock().unwrap();
        inner.lifters.llvm.module_name.clone()
    }

    #[setter]
    pub fn set_module_name(&mut self, value: String) {
        let mut inner = self.inner.lock().unwrap();
        inner.lifters.llvm.module_name = value;
    }

    #[getter]
    pub fn get_verify(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.lifters.llvm.verify
    }

    #[setter]
    pub fn set_verify(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.lifters.llvm.verify = value;
    }

    #[getter]
    pub fn get_mode(&self) -> String {
        let inner = self.inner.lock().unwrap();
        match inner.lifters.llvm.mode {
            binlex::irs::llvm::Mode::Reconstruct => "reconstruct",
            binlex::irs::llvm::Mode::Intrinsic => "intrinsic",
            binlex::irs::llvm::Mode::Lir => "semantic",
        }
        .to_string()
    }

    #[setter]
    pub fn set_mode(&mut self, value: String) -> PyResult<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.lifters.llvm.mode = match value.as_str() {
            "reconstruct" => binlex::irs::llvm::Mode::Reconstruct,
            "intrinsic" => binlex::irs::llvm::Mode::Intrinsic,
            "semantic" => binlex::irs::llvm::Mode::Lir,
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
pub struct ConfigLiftersVex {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigLiftersVex {
    #[getter]
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.lifters.vex.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.lifters.vex.enabled = value;
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
    /// Return whether minimal mode is enabled.
    pub fn get_minimal(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.minimal
    }

    #[setter]
    pub fn set_minimal(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.minimal = value;
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
    /// Return the index storage configuration group.
    pub fn get_index(&self) -> PyResult<ConfigIndex> {
        Ok(ConfigIndex {
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

    #[getter]
    /// Return the decompiler configuration group.
    pub fn get_decompiler(&self) -> PyResult<ConfigDecompiler> {
        Ok(ConfigDecompiler {
            inner: Arc::clone(&self.inner),
        })
    }

    #[getter]
    /// Return the lifter configuration group.
    pub fn get_lifters(&self) -> PyResult<ConfigLifters> {
        Ok(ConfigLifters {
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

impl Default for Configuration {
    fn default() -> Self {
        Self::new()
    }
}

#[pyclass]
pub struct ConfigDisassembler {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pyclass]
pub struct ConfigDecompiler {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pyclass]
pub struct ConfigDecompilerLir {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pyclass]
pub struct ConfigDecompilerMir {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pyclass]
pub struct ConfigDecompilerOptimize {
    pub inner: Arc<Mutex<InnerConfig>>,
    pub stage: &'static str,
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

#[pymethods]
impl ConfigDecompiler {
    #[getter]
    pub fn get_lir(&self) -> ConfigDecompilerLir {
        ConfigDecompilerLir {
            inner: Arc::clone(&self.inner),
        }
    }

    #[getter]
    pub fn get_mir(&self) -> ConfigDecompilerMir {
        ConfigDecompilerMir {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[pymethods]
impl ConfigDecompilerLir {
    #[getter]
    pub fn get_optimize(&self) -> ConfigDecompilerOptimize {
        ConfigDecompilerOptimize {
            inner: Arc::clone(&self.inner),
            stage: "lir",
        }
    }
}

#[pymethods]
impl ConfigDecompilerMir {
    #[getter]
    pub fn get_optimize(&self) -> ConfigDecompilerOptimize {
        ConfigDecompilerOptimize {
            inner: Arc::clone(&self.inner),
            stage: "mir",
        }
    }
}

#[pymethods]
impl ConfigDecompilerOptimize {
    #[getter]
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        match self.stage {
            "lir" => inner.decompiler.lir.optimize.enabled,
            "mir" => inner.decompiler.mir.optimize.enabled,
            _ => false,
        }
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        match self.stage {
            "lir" => inner.decompiler.lir.optimize.enabled = value,
            "mir" => inner.decompiler.mir.optimize.enabled = value,
            _ => {}
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
pub struct ConfigIndex {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigIndex {
    #[getter]
    pub fn get_local(&self) -> ConfigIndexLocal {
        ConfigIndexLocal {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[pyclass]
pub struct ConfigIndexLocal {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigIndexLocal {
    #[getter]
    pub fn get_directory(&self) -> String {
        let inner = self.inner.lock().unwrap();
        inner.index.local.directory.clone()
    }

    #[setter]
    pub fn set_directory(&mut self, value: String) {
        let mut inner = self.inner.lock().unwrap();
        inner.index.local.directory = value;
    }

    #[getter]
    pub fn get_dimensions(&self) -> Option<usize> {
        let inner = self.inner.lock().unwrap();
        inner.index.local.dimensions
    }

    #[setter]
    pub fn set_dimensions(&mut self, value: Option<usize>) {
        let mut inner = self.inner.lock().unwrap();
        inner.index.local.dimensions = value;
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
    m.add_class::<ConfigEntityEmbeddings>()?;
    m.add_class::<ConfigEntityEmbeddingsLLVM>()?;
    m.add_class::<ConfigEntityLifters>()?;
    m.add_class::<ConfigEntityLifterLLVM>()?;
    m.add_class::<ConfigEntityLifterVex>()?;
    m.add_class::<ConfigLifters>()?;
    m.add_class::<ConfigLiftersLLVM>()?;
    m.add_class::<ConfigLiftersVex>()?;
    m.add_class::<ConfigEmbeddings>()?;
    m.add_class::<ConfigEmbeddingsLLVM>()?;
    m.add_class::<ConfigFunctions>()?;
    m.add_class::<ConfigBlocks>()?;
    m.add_class::<ConfigInstructions>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.config.config", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.config.config")?;
    Ok(())
}
