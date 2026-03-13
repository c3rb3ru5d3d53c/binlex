use std::fmt;
use std::io::{Error, ErrorKind};

use libvex::{Arch, TranslateArgs, TranslateError, VexEndness, ir::IRSB};
use serde::{Deserialize, Serialize};
use serde_json;

use crate::Binary;
use crate::global::Architecture;
use crate::Config;

const BUFFER_PADDING: usize = 64;

#[derive(Serialize, Deserialize, Clone)]
pub struct LifterJson {
    pub architecture: String,
    pub address: u64,
    pub bytes: String,
    pub ir: String,
}

#[allow(dead_code)]
#[derive(Clone)]
pub struct LifterJsonDeserializer {
    pub json: LifterJson,
    pub config: Config,
}

impl LifterJsonDeserializer {
    #[allow(dead_code)]
    pub fn new(string: String, config: Config) -> Result<Self, Error> {
        let json: LifterJson =
            serde_json::from_str(&string).map_err(|error| Error::other(format!("{}", error)))?;
        let architecture = Architecture::from_string(&json.architecture)?;
        match architecture {
            Architecture::AMD64 | Architecture::I386 => {}
            Architecture::CIL | Architecture::UNKNOWN => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("unsupported VEX architecture: {}", architecture),
                ));
            }
        }
        Ok(Self { json, config })
    }

    #[allow(dead_code)]
    pub fn bytes(&self) -> Result<Vec<u8>, Error> {
        Binary::from_hex(&self.json.bytes).map_err(Error::other)
    }

    #[allow(dead_code)]
    pub fn address(&self) -> u64 {
        self.json.address
    }

    #[allow(dead_code)]
    pub fn architecture(&self) -> Result<Architecture, Error> {
        Architecture::from_string(&self.json.architecture)
    }

    #[allow(dead_code)]
    pub fn ir(&self) -> Result<String, Error> {
        let architecture = self.architecture()?;
        let bytes = self.bytes()?;
        let mut lifter = Lifter::new(architecture, &bytes, self.address(), self.config.clone())?;
        lifter
            .ir()
            .map(|irsb| irsb.to_string())
            .map_err(|error| Error::other(format!("{:?}", error)))
    }

    #[allow(dead_code)]
    pub fn process(&self) -> Result<LifterJson, Error> {
        let architecture = self.architecture()?;
        let bytes = self.bytes()?;
        let mut lifter = Lifter::new(architecture, &bytes, self.address(), self.config.clone())?;
        lifter
            .process()
            .map_err(|error| Error::other(format!("{:?}", error)))
    }

    #[allow(dead_code)]
    pub fn json(&self) -> Result<String, Error> {
        let result = serde_json::to_string(&self.json)?;
        Ok(result)
    }

    #[allow(dead_code)]
    pub fn print(&self) {
        if let Ok(json) = self.json() {
            println!("{}", json);
        }
    }
}

pub struct Lifter {
    translator: TranslateArgs,
    guest_architecture: Architecture,
    guest_bytes: Vec<u8>,
    guest_address: u64,
    pub config: Config,
}

impl Lifter {
    pub fn new(
        architecture: Architecture,
        bytes: &[u8],
        address: u64,
        config: Config,
    ) -> Result<Self, Error> {
        let guest_arch = match architecture {
            Architecture::AMD64 => Arch::VexArchAMD64,
            Architecture::I386 => Arch::VexArchX86,
            Architecture::CIL | Architecture::UNKNOWN => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("unsupported VEX architecture: {}", architecture),
                ));
            }
        };
        let host_arch = if cfg!(target_arch = "aarch64") {
            Arch::VexArchARM64
        } else {
            Arch::VexArchAMD64
        };
        let mut guest_bytes = Vec::with_capacity(bytes.len() + BUFFER_PADDING);
        guest_bytes.extend_from_slice(bytes);
        guest_bytes.resize(bytes.len() + BUFFER_PADDING, 0);
        Ok(Self {
            translator: TranslateArgs::new(guest_arch, host_arch, VexEndness::VexEndnessLE),
            guest_architecture: architecture,
            guest_bytes,
            guest_address: address,
            config,
        })
    }

    pub fn ir(&mut self) -> Result<IRSB<'_>, TranslateError> {
        self.translator
            .front_end(self.guest_bytes.as_ptr(), self.guest_address)
    }

    #[allow(dead_code)]
    pub fn address(&self) -> u64 {
        self.guest_address
    }

    #[allow(dead_code)]
    pub fn architecture(&self) -> Architecture {
        self.guest_architecture
    }

    #[allow(dead_code)]
    pub fn bytes(&self) -> &[u8] {
        let len = self.guest_bytes.len().saturating_sub(BUFFER_PADDING);
        &self.guest_bytes[..len]
    }

    pub fn process(&mut self) -> Result<LifterJson, TranslateError> {
        let ir = self.ir()?.to_string();
        Ok(LifterJson {
            architecture: self.architecture().to_string(),
            address: self.guest_address,
            bytes: Binary::to_hex(&self.bytes()),
            ir,
        })
    }
}

impl fmt::Display for Lifter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Lifter")
    }
}
