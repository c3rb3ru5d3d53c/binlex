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

use dirs;
use serde;
use serde::{Deserialize, Serialize};
use std::env;
use std::io::Error;
use std::io::ErrorKind;
use std::{fs, path::PathBuf};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const AUTHOR: &str = "@c3rb3ru5d3d53c";
pub const DIRECTORY: &str = "binlex";
pub const FILE_NAME: &str = "binlex.toml";

// #[derive(Serialize, Deserialize, Clone)]
// pub struct ConfigHomologuesMinhash {
//     pub enabled: bool,
//     pub threshold: f64,
// }

// #[derive(Serialize, Deserialize, Clone)]
// pub struct ConfigHomologuesTLSH {
//     pub enabled: bool,
//     pub threshold: f64,
// }

// #[derive(Serialize, Deserialize, Clone)]
// pub struct ConfigHomologuesHashing {
//     pub minhash: ConfigHomologuesMinhash,
//     pub tlsh: ConfigHomologuesTLSH,
// }

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigHomologues {
    pub enabled: bool,
    pub maximum: usize,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigBlockInstructions {
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigFunctionBlocks {
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigInstructions {
    pub enabled: bool,
    pub hashing: ConfigHashing,
    pub heuristics: ConfigHeuristics,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigBlocks {
    pub enabled: bool,
    pub instructions: ConfigBlockInstructions,
    pub hashing: ConfigHashing,
    pub heuristics: ConfigHeuristics,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigChromosomes {
    pub hashing: ConfigHashing,
    pub heuristics: ConfigHeuristics,
    pub homologues: ConfigHomologues,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigFunctions {
    pub enabled: bool,
    pub blocks: ConfigFunctionBlocks,
    pub hashing: ConfigHashing,
    pub heuristics: ConfigHeuristics,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigFile {
    pub hashing: ConfigHashing,
    pub heuristics: ConfigHeuristics,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigFormats {
    pub file: ConfigFile,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Config {
    pub general: ConfigGeneral,
    pub formats: ConfigFormats,
    pub instructions: ConfigInstructions,
    pub blocks: ConfigBlocks,
    pub functions: ConfigFunctions,
    pub chromosomes: ConfigChromosomes,
    pub mmap: ConfigMmap,
    pub disassembler: ConfigDisassembler,
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
pub struct ConfigHeuristics {
    pub features: ConfigHeuristicFeatures,
    pub entropy: ConfigHeuristicEntropy,
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
    pub sha256: ConfigSHA256,
    pub tlsh: ConfigTLSH,
    pub minhash: ConfigMinhash,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigFileHashes {
    pub sha256: ConfigSHA256,
    pub tlsh: ConfigTLSH,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigGeneral {
    pub threads: usize,
    pub minimal: bool,
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
pub struct ConfigSHA256 {
    pub enabled: bool,
}

impl Config {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Config {
            general: ConfigGeneral {
                threads: 1,
                minimal: false,
                debug: false,
            },
            formats: ConfigFormats {
                file: ConfigFile {
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
                    heuristics: ConfigHeuristics {
                        features: ConfigHeuristicFeatures { enabled: true },
                        entropy: ConfigHeuristicEntropy { enabled: true },
                    },
                },
            },
            instructions: ConfigInstructions {
                enabled: false,
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
                heuristics: ConfigHeuristics {
                    features: ConfigHeuristicFeatures { enabled: true },
                    entropy: ConfigHeuristicEntropy { enabled: true },
                },
            },
            blocks: ConfigBlocks {
                enabled: true,
                instructions: ConfigBlockInstructions { enabled: false },
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
                heuristics: ConfigHeuristics {
                    features: ConfigHeuristicFeatures { enabled: true },
                    entropy: ConfigHeuristicEntropy { enabled: true },
                },
            },
            functions: ConfigFunctions {
                enabled: true,
                blocks: ConfigFunctionBlocks { enabled: true },
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
                heuristics: ConfigHeuristics {
                    features: ConfigHeuristicFeatures { enabled: true },
                    entropy: ConfigHeuristicEntropy { enabled: true },
                },
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
                heuristics: ConfigHeuristics {
                    features: ConfigHeuristicFeatures { enabled: true },
                    entropy: ConfigHeuristicEntropy { enabled: true },
                },
                homologues: ConfigHomologues {
                    enabled: true,
                    maximum: 4,
                },
            },
            mmap: ConfigMmap {
                directory: Config::default_file_mapping_directory(),
                cache: ConfigMmapCache { enabled: false },
            },
            disassembler: ConfigDisassembler {
                sweep: ConfigDisassemblerSweep { enabled: true },
            },
        }
    }

    pub fn enable_minimal(&mut self) {
        self.general.minimal = true;
        self.disable_heuristics();
        self.disable_hashing();
        self.functions.blocks.enabled = false;
        self.instructions.enabled = false;
        self.blocks.instructions.enabled = false;
    }

    pub fn disable_hashing(&mut self) {
        self.disable_block_hashing();
        self.disable_function_hashing();
        self.disable_chromosome_hashing();
        self.disable_file_hashing();
    }

    pub fn disable_chromosome_heuristics(&mut self) {
        self.chromosomes.heuristics.entropy.enabled = false;
        self.chromosomes.heuristics.features.enabled = false;
    }

    pub fn disable_instruction_hashing(&mut self) {
        self.instructions.hashing.sha256.enabled = false;
        self.instructions.hashing.tlsh.enabled = false;
        self.instructions.hashing.minhash.enabled = false;
    }

    pub fn disable_block_hashing(&mut self) {
        self.blocks.hashing.sha256.enabled = false;
        self.blocks.hashing.tlsh.enabled = false;
        self.blocks.hashing.minhash.enabled = false;
    }

    pub fn disable_file_hashing(&mut self) {
        self.formats.file.hashing.sha256.enabled = false;
        self.formats.file.hashing.tlsh.enabled = false;
        self.formats.file.hashing.minhash.enabled = false;
    }

    pub fn disable_file_heuristics(&mut self) {
        self.formats.file.heuristics.entropy.enabled = false;
        self.formats.file.heuristics.features.enabled = false;
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
        self.blocks.heuristics.entropy.enabled = false;
        self.blocks.heuristics.features.enabled = false;
    }

    pub fn disable_instruction_heuristics(&mut self) {
        self.instructions.heuristics.entropy.enabled = false;
        self.instructions.heuristics.features.enabled = false;
    }

    pub fn disable_function_heuristics(&mut self) {
        self.functions.heuristics.entropy.enabled = false;
        self.functions.heuristics.features.enabled = false;
    }

    // Get Default File Mapping Directory
    #[allow(dead_code)]
    pub fn default_file_mapping_directory() -> String {
        env::temp_dir()
            .join(DIRECTORY)
            .to_str()
            .expect("failed to convert file mapping directory to string")
            .to_owned()
    }

    /// Prints the Current Configuration
    #[allow(dead_code)]
    pub fn print(&self) {
        println!("{}", self.to_string().unwrap());
    }

    /// Convert Config to a TOML String
    ///
    #[allow(dead_code)]
    pub fn to_string(&self) -> Result<String, Error> {
        toml::to_string_pretty(self).map_err(Error::other)
    }

    /// Reads the Configuration TOML from a File Path
    pub fn from_file(file_path: &str) -> Result<Config, Error> {
        let toml_string = fs::read_to_string(file_path)?;
        let config: Config = toml::from_str(&toml_string).map_err(|error| {
            Error::new(
                ErrorKind::InvalidData,
                format!(
                    "failed to read configuration file {}\n\n{}",
                    file_path, error
                ),
            )
        })?;
        Ok(config)
    }

    /// Write the configuration TOML to a file
    #[allow(dead_code)]
    pub fn write_to_file(&self, file_path: &str) -> Result<(), Error> {
        let toml_string = self
            .to_string()
            .expect("failed to serialize binlex configration to toml format");
        fs::write(file_path, toml_string)?;
        Ok(())
    }

    /// Writes Default TOML Configuration File To Configuration Directory
    #[allow(dead_code)]
    pub fn write_default(&self) -> Result<(), Error> {
        if let Some(config_directory) = dirs::config_dir() {
            let config_file_path: PathBuf =
                config_directory.join(format!("{}/{}", DIRECTORY, FILE_NAME));
            if let Some(parent_directory) = config_file_path.parent() {
                if !parent_directory.exists() {
                    fs::create_dir_all(parent_directory)
                        .expect("failed to create binlex configuration directory");
                }
            }
            if !config_file_path.exists() {
                return self.write_to_file(config_file_path.to_str().unwrap());
            }
        }
        Err(Error::other("default configuration already exists"))
    }

    /// Reads the default TOML Configuration File
    #[allow(dead_code)]
    pub fn from_default(&mut self) -> Result<(), Error> {
        if let Some(config_directory) = dirs::config_dir() {
            let config_file_path: PathBuf =
                config_directory.join(format!("{}/{}", DIRECTORY, FILE_NAME));
            if config_file_path.exists() {
                match Config::from_file(config_file_path.to_str().unwrap()) {
                    Ok(config) => {
                        return {
                            *self = config;
                            Ok(())
                        }
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        Err(Error::other(
            "unable to read binlex default configuration file",
        ))
    }
}

impl Default for Config {
    fn default() -> Self {
        Config::new()
    }
}
