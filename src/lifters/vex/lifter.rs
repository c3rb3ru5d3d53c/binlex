use std::io::{Error, ErrorKind};

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::Config;
use crate::core::Architecture;
use crate::hex;

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
        hex::decode(&self.json.bytes).map_err(Error::other)
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
        lifter.ir()
    }

    #[allow(dead_code)]
    pub fn process(&self) -> Result<LifterJson, Error> {
        let architecture = self.architecture()?;
        let bytes = self.bytes()?;
        let mut lifter = Lifter::new(architecture, &bytes, self.address(), self.config.clone())?;
        lifter.process()
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
    architecture: Architecture,
    bytes: Vec<u8>,
    address: u64,
    config: Config,
}

impl Lifter {
    pub fn new(
        architecture: Architecture,
        bytes: &[u8],
        address: u64,
        config: Config,
    ) -> Result<Self, Error> {
        match architecture {
            Architecture::AMD64 | Architecture::I386 => {}
            Architecture::CIL | Architecture::UNKNOWN => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("unsupported VEX architecture: {}", architecture),
                ));
            }
        }
        #[cfg(target_os = "windows")]
        {
            let _ = bytes;
            let _ = address;
            let _ = config;
            Err(Error::new(
                ErrorKind::Unsupported,
                "VEX worker backend is not supported on Windows",
            ))
        }
        #[cfg(not(target_os = "windows"))]
        {
            Ok(Self {
                architecture,
                bytes: bytes.to_vec(),
                address,
                config,
            })
        }
    }

    pub fn ir(&mut self) -> Result<String, Error> {
        #[cfg(target_os = "windows")]
        {
            Err(Error::new(
                ErrorKind::Unsupported,
                "VEX worker backend is not supported on Windows",
            ))
        }
        #[cfg(not(target_os = "windows"))]
        {
            Ok(self.execute()?.ir)
        }
    }

    #[allow(dead_code)]
    pub fn address(&self) -> u64 {
        #[cfg(target_os = "windows")]
        {
            0
        }
        #[cfg(not(target_os = "windows"))]
        {
            self.address
        }
    }

    #[allow(dead_code)]
    pub fn architecture(&self) -> Architecture {
        #[cfg(target_os = "windows")]
        {
            Architecture::UNKNOWN
        }
        #[cfg(not(target_os = "windows"))]
        {
            self.architecture
        }
    }

    #[allow(dead_code)]
    pub fn bytes(&self) -> &[u8] {
        #[cfg(target_os = "windows")]
        {
            &[]
        }
        #[cfg(not(target_os = "windows"))]
        {
            &self.bytes
        }
    }

    pub fn process(&mut self) -> Result<LifterJson, Error> {
        #[cfg(target_os = "windows")]
        {
            Err(Error::new(
                ErrorKind::Unsupported,
                "VEX worker backend is not supported on Windows",
            ))
        }
        #[cfg(not(target_os = "windows"))]
        {
            self.execute()
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn execute(&self) -> Result<LifterJson, Error> {
        let response = crate::runtime::transports::ipc::execute_external(
            "vex",
            &self.config.processors,
            json!({
                "type": "lift",
                "architecture": self.architecture.to_string(),
                "address": self.address,
                "bytes": hex::encode(&self.bytes),
            }),
        )
        .map_err(|error: crate::runtime::ProcessorError| Error::other(error.to_string()))?;

        let ir = response
            .get("ir")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| Error::other("vex processor response did not contain ir"))?
            .to_string();

        Ok(LifterJson {
            architecture: self.architecture.to_string(),
            address: self.address,
            bytes: hex::encode(&self.bytes),
            ir,
        })
    }
}
