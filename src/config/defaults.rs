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
    ConfigBlocks, ConfigChromosomes, ConfigData, ConfigDisassembler, ConfigDisassemblerSweep,
    ConfigEmbeddings, ConfigFile, ConfigFormats, ConfigFunctions, ConfigImaging,
    ConfigImagingMinhash, ConfigImagingTLSH, ConfigIrs, ConfigMarkov, ConfigMinhash, ConfigMmap,
    ConfigMmapCache, ConfigTLSH, Configuration,
};
use std::env;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const AUTHOR: &str = "@c3rb3ru5d3d53c";
pub const DIRECTORY: &str = "binlex";
pub const FILE_NAME: &str = "binlex.toml";
pub const RAYON_WORKER_STACK_SIZE: usize = 16 * 1024 * 1024;

impl Configuration {
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
            debug: false,
            formats: ConfigFormats {
                file: ConfigFile {
                    tlsh: ConfigTLSH {
                        minimum_byte_size: 50,
                    },
                },
            },
            imaging: ConfigImaging {
                tlsh: ConfigImagingTLSH {
                    minimum_byte_size: 50,
                },
                minhash: ConfigImagingMinhash {
                    number_of_hashes: 64,
                    shingle_size: 4,
                    maximum_byte_size_enabled: false,
                    maximum_byte_size: 50,
                    seed: 0,
                },
            },
            blocks: ConfigBlocks {
                tlsh: ConfigTLSH {
                    minimum_byte_size: 50,
                },
                minhash: ConfigMinhash {
                    number_of_hashes: 64,
                    shingle_size: 4,
                    maximum_byte_size_enabled: false,
                    maximum_byte_size: 50,
                    seed: 0,
                },
            },
            functions: ConfigFunctions {
                tlsh: ConfigTLSH {
                    minimum_byte_size: 50,
                },
                minhash: ConfigMinhash {
                    number_of_hashes: 64,
                    shingle_size: 4,
                    maximum_byte_size_enabled: false,
                    maximum_byte_size: 50,
                    seed: 0,
                },
                markov: ConfigMarkov {
                    damping: 0.85,
                    tolerance: 1e-9,
                    max_iterations: 100,
                },
            },
            chromosomes: ConfigChromosomes {
                tlsh: ConfigTLSH {
                    minimum_byte_size: 50,
                },
                minhash: ConfigMinhash {
                    number_of_hashes: 64,
                    shingle_size: 4,
                    maximum_byte_size_enabled: false,
                    maximum_byte_size: 50,
                    seed: 0,
                },
            },
            mmap: ConfigMmap {
                directory: Configuration::default_file_mapping_directory(),
                cache: ConfigMmapCache { enabled: false },
            },
            disassembler: ConfigDisassembler {
                sweep: ConfigDisassemblerSweep { enabled: true },
            },
            irs: ConfigIrs::default(),
            embeddings: ConfigEmbeddings::default(),
        })
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

impl Default for Configuration {
    fn default() -> Self {
        Configuration::new()
    }
}
