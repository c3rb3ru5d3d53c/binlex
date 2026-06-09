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

use crate::irs::llvm::Mode as LlvmMode;
use serde::{Deserialize, Serialize};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigFileRoot {
    #[serde(rename = "binlex")]
    pub binlex: ConfigData,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigHashing {
    pub tlsh: ConfigTLSH,
    pub minhash: ConfigMinhash,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigFunctions {
    #[serde(default)]
    pub markov: ConfigMarkov,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigEmbeddings {
    #[serde(default)]
    pub llvm: ConfigEmbeddingsLLVM,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigEmbeddingsLLVM {
    pub dimensions: usize,
    pub device: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigIrs {
    #[serde(default)]
    pub llvm: ConfigIrsLLVM,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigIrsLLVM {
    pub module_name: String,
    pub verify: bool,
    #[serde(default)]
    pub mode: LlvmMode,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigData {
    pub threads: usize,
    pub debug: bool,
    pub hashing: ConfigHashing,
    pub functions: ConfigFunctions,
    pub mmap: ConfigMmap,
    pub disassembler: ConfigDisassembler,
    #[serde(default)]
    pub irs: ConfigIrs,
    #[serde(default)]
    pub embeddings: ConfigEmbeddings,
}

#[derive(Clone)]
pub struct Configuration(pub(crate) Arc<ConfigData>);

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigDisassembler {
    pub sweep: ConfigDisassemblerSweep,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigDisassemblerSweep {
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigMarkov {
    pub damping: f64,
    pub tolerance: f64,
    pub max_iterations: usize,
}

impl Default for ConfigMarkov {
    fn default() -> Self {
        Self {
            damping: 0.85,
            tolerance: 1e-9,
            max_iterations: 100,
        }
    }
}

impl Default for ConfigIrsLLVM {
    fn default() -> Self {
        Self {
            module_name: "binlex".to_string(),
            verify: true,
            mode: LlvmMode::Reconstruct,
        }
    }
}

impl Default for ConfigIrs {
    fn default() -> Self {
        Self {
            llvm: ConfigIrsLLVM::default(),
        }
    }
}

impl Default for ConfigEmbeddingsLLVM {
    fn default() -> Self {
        Self {
            dimensions: 64,
            device: "cpu".to_string(),
        }
    }
}

impl Default for ConfigEmbeddings {
    fn default() -> Self {
        Self {
            llvm: ConfigEmbeddingsLLVM::default(),
        }
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
    pub number_of_hashes: usize,
    pub shingle_size: usize,
    pub maximum_byte_size_enabled: bool,
    pub maximum_byte_size: usize,
    pub seed: u64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigTLSH {
    pub minimum_byte_size: usize,
}

impl Serialize for Configuration {
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

impl<'de> Deserialize<'de> for Configuration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        ConfigFileRoot::deserialize(deserializer).map(|root| Self::from_data(root.binlex))
    }
}

impl Deref for Configuration {
    type Target = ConfigData;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl DerefMut for Configuration {
    fn deref_mut(&mut self) -> &mut Self::Target {
        Arc::make_mut(&mut self.0)
    }
}
