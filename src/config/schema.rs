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
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigBlocks {
    pub enabled: bool,
    pub hashing: ConfigHashing,
    pub entropy: ConfigHeuristicEntropy,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigChromosomes {
    pub hashing: ConfigHashing,
    pub features: ConfigHeuristicFeatures,
    pub entropy: ConfigHeuristicEntropy,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigFunctions {
    pub enabled: bool,
    pub hashing: ConfigHashing,
    pub entropy: ConfigHeuristicEntropy,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigFile {
    pub hashing: ConfigFileHashing,
    pub entropy: ConfigHeuristicEntropy,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigFormats {
    pub file: ConfigFile,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigImaging {
    pub hashing: ConfigImagingHashing,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigData {
    pub general: ConfigGeneral,
    pub server: ConfigServer,
    pub formats: ConfigFormats,
    pub imaging: ConfigImaging,
    pub instructions: ConfigInstructions,
    pub blocks: ConfigBlocks,
    pub functions: ConfigFunctions,
    pub chromosomes: ConfigChromosomes,
    pub mmap: ConfigMmap,
    pub disassembler: ConfigDisassembler,
    #[serde(default)]
    pub processors: ConfigProcessors,
}

#[derive(Clone)]
pub struct Config(pub(crate) Arc<ConfigData>);

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct ConfigProcessor {
    pub enabled: bool,
    pub instructions: ConfigProcessorTarget,
    pub blocks: ConfigProcessorTarget,
    pub functions: ConfigProcessorTarget,
    #[serde(flatten, default)]
    pub options: BTreeMap<String, ConfigProcessorValue>,
    pub inline: ConfigProcessorTransport,
    pub ipc: ConfigProcessorTransport,
    pub http: ConfigProcessorTransport,
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
pub struct ConfigHashing {
    pub sha256: ConfigHashEnabled,
    pub tlsh: ConfigTLSH,
    pub minhash: ConfigMinhash,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigFileHashing {
    pub sha256: ConfigHashEnabled,
    pub tlsh: ConfigTLSH,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigImagingHashing {
    pub sha256: ConfigHashEnabled,
    pub tlsh: ConfigTLSH,
    pub minhash: ConfigMinhash,
    pub ahash: ConfigHashEnabled,
    pub dhash: ConfigHashEnabled,
    pub phash: ConfigHashEnabled,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigGeneral {
    pub threads: usize,
    pub minimal: bool,
    pub debug: bool,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigServer {
    pub bind: String,
    #[serde(default)]
    pub debug: bool,
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
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Config {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        ConfigData::deserialize(deserializer).map(Self::from_data)
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
