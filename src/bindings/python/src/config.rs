use pyo3::prelude::*;
use std::sync::{Arc, Mutex};
use binlex::Config as InnerConfig;

use binlex::Architecture as InnerBinaryArchitecture;

#[pyclass(eq)]
#[derive(PartialEq)]
pub struct Architecture {
    pub inner: InnerBinaryArchitecture,
}

#[pymethods]
impl Architecture {
    #[new]
    pub fn new(value: u16) -> Self {
        let inner = match value {
            0x00 => InnerBinaryArchitecture::AMD64,
            0x01 => InnerBinaryArchitecture::I386,
            _ => InnerBinaryArchitecture::UNKNOWN,
        };
        Architecture { inner }
    }

    #[getter]
    pub fn get_value(&self) -> u16 {
        self.inner as u16
    }
}

#[pyclass]
pub struct ConfigChromosomes {
    inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl  ConfigChromosomes {
    #[getter]
    pub fn get_hashing(&self) -> ConfigChromosomesHashing {
        ConfigChromosomesHashing {
            inner: Arc::clone(&self.inner)
        }
    }
    #[getter]
    pub fn get_heuristics(&self) -> ConfigChromosomesHeuristics {
        ConfigChromosomesHeuristics {
            inner: Arc::clone(&self.inner)
        }
    }
}

#[pyclass]
pub struct ConfigChromosomesHeuristics {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigChromosomesHeuristics {
    #[getter]
    pub fn get_features(&self) -> ConfigChromosomesHeuristicsFeatures {
        ConfigChromosomesHeuristicsFeatures {
            inner: Arc::clone(&self.inner)
        }
    }
    #[getter]
    pub fn get_normalized(&self) -> ConfigChromosomesHeuristicsNormalization {
        ConfigChromosomesHeuristicsNormalization {
            inner: Arc::clone(&self.inner)
        }
    }
    #[getter]
    pub fn get_entropy(&self) -> ConfigChromosomesHeuristicsEntropy {
        ConfigChromosomesHeuristicsEntropy {
            inner: Arc::clone(&self.inner)
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
            inner: Arc::clone(&self.inner)
        }
    }

    #[getter]
    pub fn get_tlsh(&self) -> ConfigChromosomesHashingTLSH {
        ConfigChromosomesHashingTLSH {
            inner: Arc::clone(&self.inner)
        }
    }

    #[getter]
    pub fn get_minhash(&self) -> ConfigChromosomesHashingMinhash {
        ConfigChromosomesHashingMinhash {
            inner: Arc::clone(&self.inner)
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
        inner.chromosomes.heuristics.entropy.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.chromosomes.heuristics.entropy.enabled = value;
    }
}

#[pyclass]
pub struct ConfigChromosomesHeuristicsNormalization {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigChromosomesHeuristicsNormalization {
    #[getter]
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.chromosomes.heuristics.normalized.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.chromosomes.heuristics.normalized.enabled = value;
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
        inner.chromosomes.heuristics.features.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.chromosomes.heuristics.features.enabled = value;
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
impl  ConfigFunctions {
    #[getter]
    pub fn get_hashing(&self) -> ConfigFunctionsHashing {
        ConfigFunctionsHashing {
            inner: Arc::clone(&self.inner)
        }
    }
    #[getter]
    pub fn get_heuristics(&self) -> ConfigFunctionsHeuristics {
        ConfigFunctionsHeuristics {
            inner: Arc::clone(&self.inner)
        }
    }
}

#[pyclass]
pub struct ConfigFunctionsHeuristics {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigFunctionsHeuristics {
    #[getter]
    pub fn get_features(&self) -> ConfigFunctionsHeuristicsFeatures {
        ConfigFunctionsHeuristicsFeatures {
            inner: Arc::clone(&self.inner)
        }
    }
    #[getter]
    pub fn get_normalized(&self) -> ConfigFunctionsHeuristicsNormalization {
        ConfigFunctionsHeuristicsNormalization {
            inner: Arc::clone(&self.inner)
        }
    }
    #[getter]
    pub fn get_entropy(&self) -> ConfigFunctionsHeuristicsEntropy {
        ConfigFunctionsHeuristicsEntropy {
            inner: Arc::clone(&self.inner)
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
            inner: Arc::clone(&self.inner)
        }
    }

    #[getter]
    pub fn get_tlsh(&self) -> ConfigFunctionsHashingTLSH {
        ConfigFunctionsHashingTLSH {
            inner: Arc::clone(&self.inner)
        }
    }

    #[getter]
    pub fn get_minhash(&self) -> ConfigFunctionsHashingMinhash {
        ConfigFunctionsHashingMinhash {
            inner: Arc::clone(&self.inner)
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
        inner.functions.heuristics.entropy.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.functions.heuristics.entropy.enabled = value;
    }
}

#[pyclass]
pub struct ConfigFunctionsHeuristicsNormalization {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigFunctionsHeuristicsNormalization {
    #[getter]
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.functions.heuristics.normalized.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.functions.heuristics.normalized.enabled = value;
    }
}

#[pyclass]
pub struct ConfigFunctionsHeuristicsFeatures {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigFunctionsHeuristicsFeatures {
    #[getter]
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.functions.heuristics.features.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.functions.heuristics.features.enabled = value;
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
impl  ConfigBlocks {
    #[getter]
    pub fn get_hashing(&self) -> ConfigBlocksHashing {
        ConfigBlocksHashing {
            inner: Arc::clone(&self.inner)
        }
    }
    #[getter]
    pub fn get_heuristics(&self) -> ConfigBlocksHeuristics {
        ConfigBlocksHeuristics {
            inner: Arc::clone(&self.inner)
        }
    }
}

#[pyclass]
pub struct ConfigBlocksHeuristics {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigBlocksHeuristics {
    #[getter]
    pub fn get_features(&self) -> ConfigBlocksHeuristicsFeatures {
        ConfigBlocksHeuristicsFeatures {
            inner: Arc::clone(&self.inner)
        }
    }
    #[getter]
    pub fn get_normalized(&self) -> ConfigBlocksHeuristicsNormalization {
        ConfigBlocksHeuristicsNormalization {
            inner: Arc::clone(&self.inner)
        }
    }
    #[getter]
    pub fn get_entropy(&self) -> ConfigBlocksHeuristicsEntropy {
        ConfigBlocksHeuristicsEntropy {
            inner: Arc::clone(&self.inner)
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
            inner: Arc::clone(&self.inner)
        }
    }

    #[getter]
    pub fn get_tlsh(&self) -> ConfigBlocksHashingTLSH {
        ConfigBlocksHashingTLSH {
            inner: Arc::clone(&self.inner)
        }
    }

    #[getter]
    pub fn get_minhash(&self) -> ConfigBlocksHashingMinhash {
        ConfigBlocksHashingMinhash {
            inner: Arc::clone(&self.inner)
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
        inner.blocks.heuristics.entropy.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.blocks.heuristics.entropy.enabled = value;
    }
}

#[pyclass]
pub struct ConfigBlocksHeuristicsNormalization {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigBlocksHeuristicsNormalization {
    #[getter]
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.blocks.heuristics.normalized.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.blocks.heuristics.normalized.enabled = value;
    }
}

#[pyclass]
pub struct ConfigBlocksHeuristicsFeatures {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigBlocksHeuristicsFeatures {
    #[getter]
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.blocks.heuristics.features.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.blocks.heuristics.features.enabled = value;
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
impl  ConfigFormats {
    #[getter]
    pub fn get_file(&self) -> ConfigFormatsFile {
        ConfigFormatsFile {
            inner: Arc::clone(&self.inner)
        }
    }
}

#[pyclass]
pub struct ConfigFormatsFile {
    inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl  ConfigFormatsFile {
    #[getter]
    pub fn get_hashing(&self) -> ConfigFormatsFileHashing {
        ConfigFormatsFileHashing {
            inner: Arc::clone(&self.inner)
        }
    }
    #[getter]
    pub fn get_heuristics(&self) -> ConfigFormatsFileHeuristics {
        ConfigFormatsFileHeuristics {
            inner: Arc::clone(&self.inner)
        }
    }
}

#[pyclass]
pub struct ConfigFormatsFileHeuristics {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigFormatsFileHeuristics {
    #[getter]
    pub fn get_features(&self) -> ConfigFormatsFileHeuristicsFeatures {
        ConfigFormatsFileHeuristicsFeatures {
            inner: Arc::clone(&self.inner)
        }
    }
    #[getter]
    pub fn get_normalized(&self) -> ConfigFormatsFileHeuristicsNormalization {
        ConfigFormatsFileHeuristicsNormalization {
            inner: Arc::clone(&self.inner)
        }
    }
    #[getter]
    pub fn get_entropy(&self) -> ConfigFormatsFileHeuristicsEntropy {
        ConfigFormatsFileHeuristicsEntropy {
            inner: Arc::clone(&self.inner)
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
            inner: Arc::clone(&self.inner)
        }
    }

    #[getter]
    pub fn get_tlsh(&self) -> ConfigFormatsFileHashingTLSH {
        ConfigFormatsFileHashingTLSH {
            inner: Arc::clone(&self.inner)
        }
    }

    #[getter]
    pub fn get_minhash(&self) -> ConfigFormatsFileHashingMinhash {
        ConfigFormatsFileHashingMinhash {
            inner: Arc::clone(&self.inner)
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
        inner.formats.file.heuristics.entropy.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.formats.file.heuristics.entropy.enabled = value;
    }
}

#[pyclass]
pub struct ConfigFormatsFileHeuristicsNormalization {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigFormatsFileHeuristicsNormalization {
    #[getter]
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.formats.file.heuristics.normalized.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.formats.file.heuristics.normalized.enabled = value;
    }
}

#[pyclass]
pub struct ConfigFormatsFileHeuristicsFeatures {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigFormatsFileHeuristicsFeatures {
    #[getter]
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.formats.file.heuristics.features.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.formats.file.heuristics.features.enabled = value;
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


#[pyclass]
pub struct ConfigFormatsFileHashingMinhash {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl ConfigFormatsFileHashingMinhash {
    #[getter]
    pub fn get_enabled(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.formats.file.hashing.minhash.enabled
    }

    #[setter]
    pub fn set_enabled(&mut self, value: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.formats.file.hashing.minhash.enabled = value;
    }

    #[getter]
    pub fn get_number_of_hashes(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.formats.file.hashing.minhash.number_of_hashes
    }

    #[setter]
    pub fn set_number_of_hashes(&mut self, value: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.formats.file.hashing.minhash.number_of_hashes = value;
    }

    #[getter]
    pub fn get_shingle_size(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.formats.file.hashing.minhash.shingle_size
    }

    #[setter]
    pub fn set_shingle_size(&mut self, value: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.formats.file.hashing.minhash.shingle_size = value;
    }

    #[getter]
    pub fn get_maximum_byte_size(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.formats.file.hashing.minhash.maximum_byte_size
    }

    #[setter]
    pub fn set_maximum_byte_size(&mut self, value: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.formats.file.hashing.minhash.maximum_byte_size = value;
    }
    #[getter]
    pub fn get_seed(&self) -> u64 {
        let inner = self.inner.lock().unwrap();
        inner.formats.file.hashing.minhash.seed
    }

    #[setter]
    pub fn set_seed(&mut self, value: u64) {
        let mut inner = self.inner.lock().unwrap();
        inner.formats.file.hashing.minhash.seed = value;
    }
}

#[pyclass]
pub struct Config {
    pub inner: Arc<Mutex<InnerConfig>>,
}

#[pymethods]
impl Config {
    #[new]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(InnerConfig::new())),
        }
    }

    #[getter]
    pub fn get_general(&self) -> PyResult<ConfigGeneral> {
        Ok(ConfigGeneral {
            inner: Arc::clone(&self.inner),
        })
    }
    #[getter]
    pub fn get_formats(&self) -> PyResult<ConfigFormats> {
        Ok(ConfigFormats {
            inner: Arc::clone(&self.inner),
        })
    }

    #[getter]
    pub fn get_blocks(&self) -> PyResult<ConfigBlocks> {
        Ok(ConfigBlocks {
            inner: Arc::clone(&self.inner),
        })
    }

    #[getter]
    pub fn get_functions(&self) -> PyResult<ConfigFunctions> {
        Ok(ConfigFunctions {
            inner: Arc::clone(&self.inner),
        })
    }

    #[getter]
    pub fn get_chromosomes(&self) -> PyResult<ConfigChromosomes> {
        Ok(ConfigChromosomes {
            inner: Arc::clone(&self.inner),
        })
    }

    #[getter]
    pub fn get_mmap(&self) -> PyResult<ConfigMmap> {
        Ok(ConfigMmap {
            inner: Arc::clone(&self.inner),
        })
    }

    #[getter]
    pub fn get_disassembler(&self) -> PyResult<ConfigDisassembler> {
        Ok(ConfigDisassembler {
            inner: Arc::clone(&self.inner),
        })
    }

    pub fn enable_minimal(&mut self) {
        self.inner.lock().unwrap().enable_minimal();
    }

    pub fn disable_hashing(&mut self) {
        self.inner.lock().unwrap().disable_hashing();
    }

    pub fn disable_heuristics(&mut self) {
        self.inner.lock().unwrap().disable_heuristics();
    }

    pub fn disable_chromosome_heuristics(&mut self) {
        self.inner.lock().unwrap().disable_chromosome_heuristics();
    }

    pub fn disable_chromosome_hashing(&mut self) {
        self.inner.lock().unwrap().disable_chromosome_hashing();
    }

    pub fn disable_block_hashing(&mut self) {
        self.inner.lock().unwrap().disable_block_hashing();
    }

    pub fn disable_function_hashing(&mut self) {
        self.inner.lock().unwrap().disable_function_hashing();
    }

    pub fn disable_function_heuristics(&mut self) {
        self.inner.lock().unwrap().disable_function_heuristics();
    }

    pub fn disable_block_heuristics(&mut self) {
        self.inner.lock().unwrap().disable_block_heuristics();
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
            inner: Arc::clone(&self.inner)
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
            inner: Arc::clone(&self.inner)
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

#[pymodule]
#[pyo3(name = "config")]
pub fn config_init(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Config>()?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("binlex.config", m)?;
    m.setattr("__name__", "binlex.config")?;
    Ok(())
}
