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
    Config, ConfigBlocks, ConfigChromosomes, ConfigData, ConfigDatabaseLocal, ConfigDatabases,
    ConfigDisassembler, ConfigDisassemblerSweep, ConfigEntityLifters, ConfigFile, ConfigFormats,
    ConfigFunctions, ConfigHashEnabled, ConfigHeuristicEntropy, ConfigHeuristicFeatures,
    ConfigImaging, ConfigIndex, ConfigIndexLocal, ConfigInstructions, ConfigLifters,
    ConfigLiftersLLVM, ConfigLiftersVex, ConfigMarkov, ConfigMinhash, ConfigMmap, ConfigMmapCache,
    ConfigProcessors, ConfigSemantics, ConfigStorage, ConfigStorageLocal, ConfigTLSH,
};
use std::env;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const AUTHOR: &str = "@c3rb3ru5d3d53c";
pub const DIRECTORY: &str = "binlex";
pub const FILE_NAME: &str = "binlex.toml";

impl Config {
    pub fn resolved_threads(&self) -> usize {
        match self.threads {
            0 => std::thread::available_parallelism()
                .map(|parallelism| parallelism.get())
                .unwrap_or(1),
            threads => threads,
        }
    }

    pub fn from_data(data: ConfigData) -> Self {
        Self(std::sync::Arc::new(data))
    }

    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::from_data(ConfigData {
            threads: 0,
            minimal: false,
            debug: false,
            storage: ConfigStorage::default(),
            databases: ConfigDatabases::default(),
            index: ConfigIndex::default(),
            formats: ConfigFormats {
                file: ConfigFile {
                    sha256: ConfigHashEnabled { enabled: true },
                    tlsh: ConfigTLSH {
                        enabled: true,
                        minimum_byte_size: 50,
                    },
                    entropy: ConfigHeuristicEntropy { enabled: true },
                },
            },
            imaging: ConfigImaging {
                sha256: ConfigHashEnabled { enabled: true },
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
                ahash: ConfigHashEnabled { enabled: true },
                dhash: ConfigHashEnabled { enabled: true },
                phash: ConfigHashEnabled { enabled: true },
            },
            instructions: ConfigInstructions {
                enabled: false,
                lifters: ConfigEntityLifters::default(),
            },
            blocks: ConfigBlocks {
                enabled: true,
                sha256: ConfigHashEnabled { enabled: true },
                tlsh: ConfigTLSH {
                    enabled: false,
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
                entropy: ConfigHeuristicEntropy { enabled: true },
                lifters: ConfigEntityLifters::default(),
            },
            functions: ConfigFunctions {
                enabled: true,
                sha256: ConfigHashEnabled { enabled: true },
                tlsh: ConfigTLSH {
                    enabled: false,
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
                entropy: ConfigHeuristicEntropy { enabled: true },
                markov: ConfigMarkov {
                    enabled: true,
                    damping: 0.85,
                    tolerance: 1e-9,
                    max_iterations: 100,
                },
                lifters: ConfigEntityLifters::default(),
            },
            chromosomes: ConfigChromosomes {
                mask: ConfigHashEnabled { enabled: false },
                masked: ConfigHashEnabled { enabled: false },
                sha256: ConfigHashEnabled { enabled: true },
                tlsh: ConfigTLSH {
                    enabled: false,
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
                vector: ConfigHeuristicFeatures { enabled: false },
                entropy: ConfigHeuristicEntropy { enabled: true },
            },
            semantics: ConfigSemantics::default(),
            mmap: ConfigMmap {
                directory: Config::default_file_mapping_directory(),
                cache: ConfigMmapCache { enabled: false },
            },
            disassembler: ConfigDisassembler {
                sweep: ConfigDisassemblerSweep { enabled: true },
            },
            lifters: ConfigLifters::default(),
            processors: ConfigProcessors::default(),
        })
    }

    pub fn enable_minimal(&mut self) {
        self.minimal = true;
        self.disable_hashing();
        self.instructions.enabled = false;
        self.semantics.enabled = false;
    }

    pub fn disable_hashing(&mut self) {
        self.disable_imaging_hashing();
        self.disable_block_hashing();
        self.disable_function_hashing();
        self.disable_chromosome_hashing();
        self.disable_file_hashing();
    }

    pub fn disable_imaging_hashing(&mut self) {
        self.imaging.sha256.enabled = false;
        self.imaging.tlsh.enabled = false;
        self.imaging.minhash.enabled = false;
        self.imaging.ahash.enabled = false;
        self.imaging.dhash.enabled = false;
        self.imaging.phash.enabled = false;
    }

    pub fn disable_chromosome_heuristics(&mut self) {
        self.chromosomes.entropy.enabled = false;
        self.chromosomes.vector.enabled = false;
    }

    pub fn disable_block_hashing(&mut self) {
        self.blocks.sha256.enabled = false;
        self.blocks.tlsh.enabled = false;
        self.blocks.minhash.enabled = false;
    }

    pub fn disable_file_hashing(&mut self) {
        self.formats.file.sha256.enabled = false;
        self.formats.file.tlsh.enabled = false;
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
        self.chromosomes.sha256.enabled = false;
        self.chromosomes.tlsh.enabled = false;
        self.chromosomes.minhash.enabled = false;
    }

    pub fn disable_function_hashing(&mut self) {
        self.functions.sha256.enabled = false;
        self.functions.tlsh.enabled = false;
        self.functions.minhash.enabled = false;
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

    pub fn default_local_index_directory() -> String {
        dirs::data_local_dir()
            .or_else(dirs::data_dir)
            .unwrap_or_else(|| env::temp_dir())
            .join(DIRECTORY)
            .join("indexing")
            .to_str()
            .expect("failed to convert local index directory to string")
            .to_owned()
    }

    pub fn default_local_storage_directory() -> String {
        dirs::data_local_dir()
            .or_else(dirs::data_dir)
            .unwrap_or_else(|| env::temp_dir())
            .join(DIRECTORY)
            .join("storage")
            .to_str()
            .expect("failed to convert local storage directory to string")
            .to_owned()
    }

    pub fn default_local_database_path() -> String {
        dirs::config_dir()
            .unwrap_or_else(|| env::temp_dir())
            .join(DIRECTORY)
            .join("local.db")
            .to_str()
            .expect("failed to convert local database path to string")
            .to_owned()
    }

    pub fn default_processor_directory() -> String {
        dirs::data_local_dir()
            .or_else(dirs::data_dir)
            .unwrap_or_else(|| env::temp_dir())
            .join(DIRECTORY)
            .join("processors")
            .to_str()
            .expect("failed to convert processor directory to string")
            .to_owned()
    }
}

impl Default for Config {
    fn default() -> Self {
        Config::new()
    }
}

impl Default for ConfigIndex {
    fn default() -> Self {
        Self {
            local: ConfigIndexLocal::default(),
        }
    }
}

impl Default for ConfigDatabases {
    fn default() -> Self {
        Self {
            local: ConfigDatabaseLocal::default(),
        }
    }
}

impl Default for ConfigStorage {
    fn default() -> Self {
        Self {
            local: ConfigStorageLocal::default(),
        }
    }
}

impl Default for ConfigStorageLocal {
    fn default() -> Self {
        Self {
            directory: Config::default_local_storage_directory(),
        }
    }
}

impl Default for ConfigDatabaseLocal {
    fn default() -> Self {
        Self {
            path: Config::default_local_database_path(),
        }
    }
}

impl Default for ConfigIndexLocal {
    fn default() -> Self {
        Self {
            directory: Config::default_local_index_directory(),
            dimensions: Some(64),
        }
    }
}

impl Default for ConfigLifters {
    fn default() -> Self {
        Self {
            llvm: ConfigLiftersLLVM::default(),
            vex: ConfigLiftersVex::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::Config;

    #[test]
    fn semantics_enabled_by_default() {
        let config = Config::default();
        assert!(config.semantics.enabled);
    }

    #[test]
    fn minimal_mode_disables_semantics() {
        let mut config = Config::default();
        config.enable_minimal();
        assert!(!config.semantics.enabled);
    }
}
