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

use super::{
    Config, ConfigBlocks, ConfigChromosomes, ConfigData, ConfigDisassembler,
    ConfigDisassemblerSweep, ConfigFile, ConfigFileHashing, ConfigFormats, ConfigFunctions,
    ConfigGeneral, ConfigHashing, ConfigHeuristicEntropy, ConfigHeuristicFeatures,
    ConfigInstructions, ConfigMinhash, ConfigMmap, ConfigMmapCache, ConfigProcessors,
    ConfigSHA256, ConfigServer, ConfigTLSH,
};
use std::env;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const AUTHOR: &str = "@c3rb3ru5d3d53c";
pub const DIRECTORY: &str = "binlex";
pub const FILE_NAME: &str = "binlex.toml";

impl Config {
    pub fn from_data(data: ConfigData) -> Self {
        Self(std::sync::Arc::new(data))
    }

    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::from_data(ConfigData {
            general: ConfigGeneral {
                threads: 1,
                minimal: false,
                debug: false,
            },
            server: ConfigServer {
                bind: "127.0.0.1:5000".to_string(),
                debug: false,
            },
            formats: ConfigFormats {
                file: ConfigFile {
                    hashing: ConfigFileHashing {
                        sha256: ConfigSHA256 { enabled: true },
                        tlsh: ConfigTLSH {
                            enabled: true,
                            minimum_byte_size: 50,
                        },
                    },
                    entropy: ConfigHeuristicEntropy { enabled: true },
                },
            },
            instructions: ConfigInstructions { enabled: false },
            blocks: ConfigBlocks {
                enabled: true,
                hashing: ConfigHashing {
                    sha256: ConfigSHA256 { enabled: true },
                    tlsh: ConfigTLSH {
                        enabled: true,
                        minimum_byte_size: 50,
                    },
                    minhash: ConfigMinhash {
                        enabled: true,
                        number_of_hashes: 64,
                        shingle_size: 4,
                        maximum_byte_size_enabled: false,
                        maximum_byte_size: 50,
                        seed: 0,
                    },
                },
                entropy: ConfigHeuristicEntropy { enabled: true },
            },
            functions: ConfigFunctions {
                enabled: true,
                hashing: ConfigHashing {
                    sha256: ConfigSHA256 { enabled: true },
                    tlsh: ConfigTLSH {
                        enabled: true,
                        minimum_byte_size: 50,
                    },
                    minhash: ConfigMinhash {
                        enabled: true,
                        number_of_hashes: 64,
                        shingle_size: 4,
                        maximum_byte_size_enabled: false,
                        maximum_byte_size: 50,
                        seed: 0,
                    },
                },
                entropy: ConfigHeuristicEntropy { enabled: true },
            },
            chromosomes: ConfigChromosomes {
                hashing: ConfigHashing {
                    sha256: ConfigSHA256 { enabled: true },
                    tlsh: ConfigTLSH {
                        enabled: true,
                        minimum_byte_size: 50,
                    },
                    minhash: ConfigMinhash {
                        enabled: true,
                        number_of_hashes: 64,
                        shingle_size: 4,
                        maximum_byte_size_enabled: false,
                        maximum_byte_size: 50,
                        seed: 0,
                    },
                },
                features: ConfigHeuristicFeatures { enabled: false },
                entropy: ConfigHeuristicEntropy { enabled: true },
            },
            mmap: ConfigMmap {
                directory: Config::default_file_mapping_directory(),
                cache: ConfigMmapCache { enabled: false },
            },
            disassembler: ConfigDisassembler {
                sweep: ConfigDisassemblerSweep { enabled: true },
            },
            processors: ConfigProcessors::default(),
        })
    }

    pub fn enable_minimal(&mut self) {
        self.general.minimal = true;
        self.disable_heuristics();
        self.disable_hashing();
        self.instructions.enabled = false;
        self.disassembler.sweep.enabled = false;
    }

    pub fn disable_hashing(&mut self) {
        self.disable_block_hashing();
        self.disable_function_hashing();
        self.disable_chromosome_hashing();
        self.disable_file_hashing();
    }

    pub fn disable_chromosome_heuristics(&mut self) {
        self.chromosomes.entropy.enabled = false;
        self.chromosomes.features.enabled = false;
    }

    pub fn disable_block_hashing(&mut self) {
        self.blocks.hashing.sha256.enabled = false;
        self.blocks.hashing.tlsh.enabled = false;
        self.blocks.hashing.minhash.enabled = false;
    }

    pub fn disable_file_hashing(&mut self) {
        self.formats.file.hashing.sha256.enabled = false;
        self.formats.file.hashing.tlsh.enabled = false;
    }

    pub fn disable_file_heuristics(&mut self) {
        self.formats.file.entropy.enabled = false;
    }

    pub fn disable_heuristics(&mut self) {
        self.disable_block_heuristics();
        self.disable_function_heuristics();
        self.disable_chromosome_heuristics();
        self.disable_file_heuristics();
    }

    pub fn disable_chromosome_hashing(&mut self) {
        self.chromosomes.hashing.sha256.enabled = false;
        self.chromosomes.hashing.tlsh.enabled = false;
        self.chromosomes.hashing.minhash.enabled = false;
    }

    pub fn disable_function_hashing(&mut self) {
        self.functions.hashing.sha256.enabled = false;
        self.functions.hashing.tlsh.enabled = false;
        self.functions.hashing.minhash.enabled = false;
    }

    pub fn disable_block_heuristics(&mut self) {
        self.blocks.entropy.enabled = false;
    }

    pub fn disable_function_heuristics(&mut self) {
        self.functions.entropy.enabled = false;
    }

    #[allow(dead_code)]
    pub fn default_file_mapping_directory() -> String {
        env::temp_dir()
            .join(DIRECTORY)
            .to_str()
            .expect("failed to convert file mapping directory to string")
            .to_owned()
    }
}

impl Default for Config {
    fn default() -> Self {
        Config::new()
    }
}
