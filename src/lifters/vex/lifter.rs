use std::io::{Error, ErrorKind};

use serde::{Deserialize, Serialize};

use crate::Config;
use crate::global::Architecture;
use crate::hex;
use crate::processors::vex::{VexProcessor, VexRequest, VexResponse};

#[derive(Serialize, Deserialize, Clone)]
pub struct LifterJson {
    pub architecture: String,
    pub address: u64,
    pub bytes: String,
    pub ir: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct VexLiftRequest {
    pub architecture: Architecture,
    pub address: u64,
    pub bytes: Vec<u8>,
    pub config: Config,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct VexLiftResponse {
    pub architecture: Architecture,
    pub address: u64,
    pub bytes: Vec<u8>,
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
            let response = self.execute()?;
            Ok(LifterJson {
                architecture: response.architecture.to_string(),
                address: response.address,
                bytes: hex::encode(&response.bytes),
                ir: response.ir,
            })
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn execute(&self) -> Result<VexLiftResponse, Error> {
        let pool = crate::processing::ProcessorPool::for_processor::<VexProcessor>(
            &self.config.processors,
        )
        .map_err(|error| Error::other(error.to_string()))?;
        let response = pool
            .execute::<VexProcessor>(&VexRequest::Lift(VexLiftRequest {
                architecture: self.architecture,
                address: self.address,
                bytes: self.bytes.clone(),
                config: self.config.clone(),
            }))
            .map_err(|error: crate::processing::ProcessorError| Error::other(error.to_string()))?;

        match response {
            VexResponse::Lift(response) => Ok(response),
        }
    }
}
