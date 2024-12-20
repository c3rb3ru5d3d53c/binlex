//                    GNU LESSER GENERAL PUBLIC LICENSE
//                        Version 3, 29 June 2007
//
//  Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>
//  Everyone is permitted to copy and distribute verbatim copies
//  of this license document, but changing it is not allowed.
//
//
//   This version of the GNU Lesser General Public License incorporates
// the terms and conditions of version 3 of the GNU General Public
// License, supplemented by the additional permissions listed below.
//
//   0. Additional Definitions.
//
//   As used herein, "this License" refers to version 3 of the GNU Lesser
// General Public License, and the "GNU GPL" refers to version 3 of the GNU
// General Public License.
//
//   "The Library" refers to a covered work governed by this License,
// other than an Application or a Combined Work as defined below.
//
//   An "Application" is any work that makes use of an interface provided
// by the Library, but which is not otherwise based on the Library.
// Defining a subclass of a class defined by the Library is deemed a mode
// of using an interface provided by the Library.
//
//   A "Combined Work" is a work produced by combining or linking an
// Application with the Library.  The particular version of the Library
// with which the Combined Work was made is also called the "Linked
// Version".
//
//   The "Minimal Corresponding Source" for a Combined Work means the
// Corresponding Source for the Combined Work, excluding any source code
// for portions of the Combined Work that, considered in isolation, are
// based on the Application, and not on the Linked Version.
//
//   The "Corresponding Application Code" for a Combined Work means the
// object code and/or source code for the Application, including any data
// and utility programs needed for reproducing the Combined Work from the
// Application, but excluding the System Libraries of the Combined Work.
//
//   1. Exception to Section 3 of the GNU GPL.
//
//   You may convey a covered work under sections 3 and 4 of this License
// without being bound by section 3 of the GNU GPL.
//
//   2. Conveying Modified Versions.
//
//   If you modify a copy of the Library, and, in your modifications, a
// facility refers to a function or data to be supplied by an Application
// that uses the facility (other than as an argument passed when the
// facility is invoked), then you may convey a copy of the modified
// version:
//
//    a) under this License, provided that you make a good faith effort to
//    ensure that, in the event an Application does not supply the
//    function or data, the facility still operates, and performs
//    whatever part of its purpose remains meaningful, or
//
//    b) under the GNU GPL, with none of the additional permissions of
//    this License applicable to that copy.
//
//   3. Object Code Incorporating Material from Library Header Files.
//
//   The object code form of an Application may incorporate material from
// a header file that is part of the Library.  You may convey such object
// code under terms of your choice, provided that, if the incorporated
// material is not limited to numerical parameters, data structure
// layouts and accessors, or small macros, inline functions and templates
// (ten or fewer lines in length), you do both of the following:
//
//    a) Give prominent notice with each copy of the object code that the
//    Library is used in it and that the Library and its use are
//    covered by this License.
//
//    b) Accompany the object code with a copy of the GNU GPL and this license
//    document.
//
//   4. Combined Works.
//
//   You may convey a Combined Work under terms of your choice that,
// taken together, effectively do not restrict modification of the
// portions of the Library contained in the Combined Work and reverse
// engineering for debugging such modifications, if you also do each of
// the following:
//
//    a) Give prominent notice with each copy of the Combined Work that
//    the Library is used in it and that the Library and its use are
//    covered by this License.
//
//    b) Accompany the Combined Work with a copy of the GNU GPL and this license
//    document.
//
//    c) For a Combined Work that displays copyright notices during
//    execution, include the copyright notice for the Library among
//    these notices, as well as a reference directing the user to the
//    copies of the GNU GPL and this license document.
//
//    d) Do one of the following:
//
//        0) Convey the Minimal Corresponding Source under the terms of this
//        License, and the Corresponding Application Code in a form
//        suitable for, and under terms that permit, the user to
//        recombine or relink the Application with a modified version of
//        the Linked Version to produce a modified Combined Work, in the
//        manner specified by section 6 of the GNU GPL for conveying
//        Corresponding Source.
//
//        1) Use a suitable shared library mechanism for linking with the
//        Library.  A suitable mechanism is one that (a) uses at run time
//        a copy of the Library already present on the user's computer
//        system, and (b) will operate properly with a modified version
//        of the Library that is interface-compatible with the Linked
//        Version.
//
//    e) Provide Installation Information, but only if you would otherwise
//    be required to provide such information under section 6 of the
//    GNU GPL, and only to the extent that such information is
//    necessary to install and execute a modified version of the
//    Combined Work produced by recombining or relinking the
//    Application with a modified version of the Linked Version. (If
//    you use option 4d0, the Installation Information must accompany
//    the Minimal Corresponding Source and Corresponding Application
//    Code. If you use option 4d1, you must provide the Installation
//    Information in the manner specified by section 6 of the GNU GPL
//    for conveying Corresponding Source.)
//
//   5. Combined Libraries.
//
//   You may place library facilities that are a work based on the
// Library side by side in a single library together with other library
// facilities that are not Applications and are not covered by this
// License, and convey such a combined library under terms of your
// choice, if you do both of the following:
//
//    a) Accompany the combined library with a copy of the same work based
//    on the Library, uncombined with any other library facilities,
//    conveyed under the terms of this License.
//
//    b) Give prominent notice with the combined library that part of it
//    is a work based on the Library, and explaining where to find the
//    accompanying uncombined form of the same work.
//
//   6. Revised Versions of the GNU Lesser General Public License.
//
//   The Free Software Foundation may publish revised and/or new versions
// of the GNU Lesser General Public License from time to time. Such new
// versions will be similar in spirit to the present version, but may
// differ in detail to address new problems or concerns.
//
//   Each version is given a distinguishing version number. If the
// Library as you received it specifies that a certain numbered version
// of the GNU Lesser General Public License "or any later version"
// applies to it, you have the option of following the terms and
// conditions either of that published version or of any later version
// published by the Free Software Foundation. If the Library as you
// received it does not specify a version number of the GNU Lesser
// General Public License, you may choose any version of the GNU Lesser
// General Public License ever published by the Free Software Foundation.
//
//   If the Library as you received it specifies that a proxy can decide
// whether future versions of the GNU Lesser General Public License shall
// apply, that proxy's public statement of acceptance of any version is
// permanent authorization for you to choose that version for the
// Library.

use dirs;
use std::{fs, path::PathBuf};
use std::io::Error;
use std::io::ErrorKind;
use std::env;
use serde::{Deserialize, Serialize};
use serde;

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
    //pub hashing: ConfigHomologuesHashing,
    //pub threshold: f64,
    //pub wildcard_ratio: f64,
    pub maximum: usize,
    //pub size: usize,
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
    pub threshold: f64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigTLSH {
    pub enabled: bool,
    pub minimum_byte_size: usize,
    pub threshold: f64,
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
                        sha256: ConfigSHA256 {
                            enabled: true,
                        },
                        tlsh: ConfigTLSH {
                            enabled: true,
                            minimum_byte_size: 50,
                            threshold: 200.0,
                        },
                        minhash: ConfigMinhash {
                            enabled: true,
                            number_of_hashes: 64,
                            shingle_size: 4,
                            maximum_byte_size_enabled: false,
                            maximum_byte_size: 50,
                            seed: 0,
                            threshold: 0.75,
                        }
                    },
                    heuristics: ConfigHeuristics {
                        features: ConfigHeuristicFeatures {
                            enabled: true,
                        },
                        entropy: ConfigHeuristicEntropy {
                            enabled: true,
                        }
                    }
                }
            },
            instructions: ConfigInstructions {
                enabled: false,
                hashing: ConfigHashing {
                    sha256: ConfigSHA256 {
                        enabled: true,
                    },
                    tlsh: ConfigTLSH {
                        enabled: true,
                        minimum_byte_size: 50,
                        threshold: 200.0,
                    },
                    minhash: ConfigMinhash {
                        enabled: true,
                        number_of_hashes: 64,
                        shingle_size: 4,
                        maximum_byte_size_enabled: false,
                        maximum_byte_size: 50,
                        seed: 0,
                        threshold: 0.75,
                    }
                },
                heuristics: ConfigHeuristics {
                    features: ConfigHeuristicFeatures {
                        enabled: true,
                    },
                    entropy: ConfigHeuristicEntropy {
                        enabled: true,
                    }
                }
            },
            blocks: ConfigBlocks {
                enabled: true,
                instructions: ConfigBlockInstructions {
                    enabled: false,
                },
                hashing: ConfigHashing {
                    sha256: ConfigSHA256 {
                        enabled: true,
                    },
                    tlsh: ConfigTLSH {
                        enabled: true,
                        minimum_byte_size: 50,
                        threshold: 200.0,
                    },
                    minhash: ConfigMinhash {
                        enabled: true,
                        number_of_hashes: 64,
                        shingle_size: 4,
                        maximum_byte_size_enabled: false,
                        maximum_byte_size: 50,
                        seed: 0,
                        threshold: 0.75,
                    }
                },
                heuristics: ConfigHeuristics {
                    features: ConfigHeuristicFeatures {
                        enabled: true,
                    },
                    entropy: ConfigHeuristicEntropy {
                        enabled: true,
                    }
                }
            },
            functions: ConfigFunctions {
                enabled: true,
                blocks: ConfigFunctionBlocks {
                    enabled: true,
                },
                hashing: ConfigHashing {
                    sha256: ConfigSHA256 {
                        enabled: true,
                    },
                    tlsh: ConfigTLSH {
                        enabled: true,
                        minimum_byte_size: 50,
                        threshold: 200.0,
                    },
                    minhash: ConfigMinhash {
                        enabled: true,
                        number_of_hashes: 64,
                        shingle_size: 4,
                        maximum_byte_size_enabled: false,
                        maximum_byte_size: 50,
                        seed: 0,
                        threshold: 0.75,
                    }
                },
                heuristics: ConfigHeuristics {
                    features: ConfigHeuristicFeatures {
                        enabled: true,
                    },
                    entropy: ConfigHeuristicEntropy {
                        enabled: true,
                    }
                }
            },
            chromosomes: ConfigChromosomes {
                hashing: ConfigHashing {
                    sha256: ConfigSHA256 {
                        enabled: true,
                    },
                    tlsh: ConfigTLSH {
                        enabled: true,
                        minimum_byte_size: 50,
                        threshold: 200.0,
                    },
                    minhash: ConfigMinhash {
                        enabled: true,
                        number_of_hashes: 64,
                        shingle_size: 4,
                        maximum_byte_size_enabled: false,
                        maximum_byte_size: 50,
                        seed: 0,
                        threshold: 0.75,
                    }
                },
                heuristics: ConfigHeuristics {
                    features: ConfigHeuristicFeatures {
                        enabled: true,
                    },
                    entropy: ConfigHeuristicEntropy {
                        enabled: true,
                    }
                },
                homologues: ConfigHomologues {
                    enabled: true,
                    maximum: 4,
                }
            },
            mmap: ConfigMmap {
                directory: Config::default_file_mapping_directory(),
                cache: ConfigMmapCache {
                    enabled: false,
                }
            },
            disassembler: ConfigDisassembler {
                sweep: ConfigDisassemblerSweep {
                    enabled: true,
                }
            }
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

    pub fn disable_instruction_hashing(&mut self){
        self.instructions.hashing.sha256.enabled = false;
        self.instructions.hashing.tlsh.enabled = false;
        self.instructions.hashing.minhash.enabled = false;
    }

    pub fn disable_block_hashing(&mut self){
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
    #[allow(dead_code)]
    pub fn to_string(&self) -> Result<String, Error> {
        toml::to_string_pretty(self).map_err(|e| Error::new(ErrorKind::Other, e))
    }

    /// Reads the Configuration TOML from a File Path
    pub fn from_file(file_path: &str) -> Result<Config, Error> {
        let toml_string = fs::read_to_string(file_path)?;
        let config: Config = toml::from_str(&toml_string)
            .map_err(|error| Error::new(ErrorKind::InvalidData, format!("failed to read configuration file {}\n\n{}", file_path, error)))?;
        Ok(config)
    }

    /// Write the configuration TOML to a file
    #[allow(dead_code)]
    pub fn write_to_file(&self, file_path: &str) -> Result<(), Error> {
        let toml_string = self.to_string()
            .expect("failed to serialize binlex configration to toml format");
        fs::write(file_path, toml_string)?;
        Ok(())
    }

    /// Writes Default TOML Configuration File To Configuration Directory
    #[allow(dead_code)]
    pub fn write_default(&self) -> Result<(), Error> {
        if let Some(config_directory) = dirs::config_dir() {
            let config_file_path: PathBuf = config_directory.join(format!("{}/{}", DIRECTORY, FILE_NAME));
            if let Some(parent_directory) = config_file_path.parent() {
                if !parent_directory.exists() {
                    fs::create_dir_all(parent_directory).expect("failed to create binlex configuration directory");
                }
            }
            if !config_file_path.exists() {
                return self.write_to_file(config_file_path.to_str().unwrap());
            }
        }
        return Err(Error::new(ErrorKind::Other, format!("default configuration already exists")));
    }

    /// Reads the default TOML Configuration File
    #[allow(dead_code)]
    pub fn from_default(&mut self) -> Result<(), Error> {
        if let Some(config_directory) = dirs::config_dir() {
            let config_file_path: PathBuf = config_directory.join(format!("{}/{}", DIRECTORY, FILE_NAME));
            if config_file_path.exists() {
                match Config::from_file(config_file_path.to_str().unwrap()) {
                    Ok(config) => return {
                        *self = config;
                        Ok(())
                    },
                    Err(error) => return Err(error),
                }
            }
        }
        return Err(Error::new(ErrorKind::Other, format!("unable to read binlex default configuration file")));
    }

}
