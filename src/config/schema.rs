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

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigFileRoot {
    #[serde(rename = "binlex")]
    pub binlex: ConfigData,
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct ConfigProcessorTarget {
    pub enabled: bool,
    #[serde(flatten, default)]
    pub options: BTreeMap<String, ConfigProcessorValue>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct ConfigProcessorTransport {
    pub enabled: bool,
    #[serde(flatten, default)]
    pub options: BTreeMap<String, ConfigProcessorValue>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct ConfigProcessorTransports {
    pub ipc: ConfigProcessorTransport,
    pub http: ConfigProcessorTransport,
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
#[serde(untagged)]
pub enum ConfigProcessorValue {
    Bool(bool),
    Integer(i64),
    Float(f64),
    String(String),
    Array(Vec<ConfigProcessorValue>),
    Table(BTreeMap<String, ConfigProcessorValue>),
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigInstructions {
    pub enabled: bool,
    #[serde(default)]
    pub semantics: ConfigInstructionsSemantics,
    #[serde(default)]
    pub lifters: ConfigEntityLifters,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigInstructionsSemantics {
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigBlocks {
    pub enabled: bool,
    pub sha256: ConfigHashEnabled,
    pub tlsh: ConfigTLSH,
    pub minhash: ConfigMinhash,
    pub entropy: ConfigHeuristicEntropy,
    #[serde(default)]
    pub lifters: ConfigEntityLifters,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigChromosomes {
    pub mask: ConfigHashEnabled,
    pub masked: ConfigHashEnabled,
    pub sha256: ConfigHashEnabled,
    pub tlsh: ConfigTLSH,
    pub minhash: ConfigMinhash,
    pub vector: ConfigHeuristicFeatures,
    pub entropy: ConfigHeuristicEntropy,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigFunctions {
    pub enabled: bool,
    pub sha256: ConfigHashEnabled,
    pub tlsh: ConfigTLSH,
    pub minhash: ConfigMinhash,
    pub entropy: ConfigHeuristicEntropy,
    #[serde(default)]
    pub markov: ConfigMarkov,
    #[serde(default)]
    pub lifters: ConfigEntityLifters,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigEntityLifters {
    #[serde(default)]
    pub llvm: ConfigEntityLifterLLVM,
    #[serde(default)]
    pub vex: ConfigEntityLifterVex,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigEntityLifterLLVM {
    pub enabled: bool,
    #[serde(default)]
    pub normalized: ConfigEntityLifterLLVMNormalized,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigEntityLifterLLVMNormalized {
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigEntityLifterVex {
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigFile {
    pub sha256: ConfigHashEnabled,
    pub tlsh: ConfigTLSH,
    pub entropy: ConfigHeuristicEntropy,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigFormats {
    pub file: ConfigFile,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigImaging {
    pub sha256: ConfigHashEnabled,
    pub tlsh: ConfigTLSH,
    pub minhash: ConfigMinhash,
    pub ahash: ConfigHashEnabled,
    pub dhash: ConfigHashEnabled,
    pub phash: ConfigHashEnabled,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigLifters {
    #[serde(default)]
    pub llvm: ConfigLiftersLLVM,
    #[serde(default)]
    pub vex: ConfigLiftersVex,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigLiftersLLVM {
    pub module_name: String,
    pub verify: bool,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigLiftersVex {
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigSemantics {
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigData {
    pub threads: usize,
    pub minimal: bool,
    pub debug: bool,
    #[serde(default)]
    pub storage: ConfigStorage,
    #[serde(default)]
    pub databases: ConfigDatabases,
    #[serde(default)]
    pub index: ConfigIndex,
    pub formats: ConfigFormats,
    pub imaging: ConfigImaging,
    pub instructions: ConfigInstructions,
    pub blocks: ConfigBlocks,
    pub functions: ConfigFunctions,
    pub chromosomes: ConfigChromosomes,
    #[serde(default)]
    pub semantics: ConfigSemantics,
    pub mmap: ConfigMmap,
    pub disassembler: ConfigDisassembler,
    #[serde(default)]
    pub lifters: ConfigLifters,
    #[serde(default)]
    pub processors: ConfigProcessors,
}

#[derive(Clone)]
pub struct Config(pub(crate) Arc<ConfigData>);

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigStorage {
    #[serde(default)]
    pub local: ConfigStorageLocal,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigStorageLocal {
    pub directory: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigDatabases {
    #[serde(default)]
    pub local: ConfigDatabaseLocal,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigDatabaseLocal {
    pub path: String,
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct ConfigProcessor {
    pub enabled: bool,
    pub instructions: ConfigProcessorTarget,
    pub blocks: ConfigProcessorTarget,
    pub functions: ConfigProcessorTarget,
    pub graph: ConfigProcessorTarget,
    pub complete: ConfigProcessorTarget,
    #[serde(flatten, default)]
    pub options: BTreeMap<String, ConfigProcessorValue>,
    pub transport: ConfigProcessorTransports,
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct ConfigProcessors {
    pub enabled: bool,
    pub path: Option<String>,
    pub processes: usize,
    pub compression: bool,
    pub restart_on_crash: bool,
    pub max_payload_bytes: usize,
    pub idle_timeout_ms: u64,
    pub max_queue_depth: usize,
    #[serde(flatten, default)]
    pub processors: BTreeMap<String, ConfigProcessor>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigDisassembler {
    pub sweep: ConfigDisassemblerSweep,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigIndex {
    #[serde(default)]
    pub local: ConfigIndexLocal,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigIndexLocal {
    pub directory: String,
    pub dimensions: Option<usize>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigDisassemblerSweep {
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigHeuristicFeatures {
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigHeuristicEntropy {
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigMarkov {
    pub enabled: bool,
    pub damping: f64,
    pub tolerance: f64,
    pub max_iterations: usize,
}

impl Default for ConfigMarkov {
    fn default() -> Self {
        Self {
            enabled: true,
            damping: 0.85,
            tolerance: 1e-9,
            max_iterations: 100,
        }
    }
}

impl Default for ConfigEntityLifterLLVMNormalized {
    fn default() -> Self {
        Self { enabled: false }
    }
}

impl Default for ConfigInstructionsSemantics {
    fn default() -> Self {
        Self { enabled: true }
    }
}

impl Default for ConfigEntityLifterLLVM {
    fn default() -> Self {
        Self {
            enabled: false,
            normalized: ConfigEntityLifterLLVMNormalized::default(),
        }
    }
}

impl Default for ConfigEntityLifters {
    fn default() -> Self {
        Self {
            llvm: ConfigEntityLifterLLVM::default(),
            vex: ConfigEntityLifterVex::default(),
        }
    }
}

impl Default for ConfigEntityLifterVex {
    fn default() -> Self {
        Self { enabled: false }
    }
}

impl Default for ConfigLiftersLLVM {
    fn default() -> Self {
        Self {
            module_name: "binlex".to_string(),
            verify: true,
        }
    }
}

impl Default for ConfigLiftersVex {
    fn default() -> Self {
        Self { enabled: true }
    }
}

impl Default for ConfigSemantics {
    fn default() -> Self {
        Self { enabled: true }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigMmap {
    pub directory: String,
    pub cache: ConfigMmapCache,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigMmapCache {
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigMinhash {
    pub enabled: bool,
    pub number_of_hashes: usize,
    pub shingle_size: usize,
    pub maximum_byte_size_enabled: bool,
    pub maximum_byte_size: usize,
    pub seed: u64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigTLSH {
    pub enabled: bool,
    pub minimum_byte_size: usize,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigHashEnabled {
    pub enabled: bool,
}

impl Serialize for Config {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        ConfigFileRoot {
            binlex: self.0.as_ref().clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Config {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        ConfigFileRoot::deserialize(deserializer).map(|root| Self::from_data(root.binlex))
    }
}

impl Deref for Config {
    type Target = ConfigData;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl DerefMut for Config {
    fn deref_mut(&mut self) -> &mut Self::Target {
        Arc::make_mut(&mut self.0)
    }
}
