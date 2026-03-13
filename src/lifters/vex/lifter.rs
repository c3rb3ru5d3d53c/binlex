use std::fmt;
use std::io::{Error, ErrorKind};

use libvex::{Arch, TranslateArgs, TranslateError, VexEndness, ir::IRSB};
use serde::{Deserialize, Serialize};

use crate::global::Architecture;
use crate::Config;

const BUFFER_PADDING: usize = 64;

#[derive(Serialize, Deserialize)]
pub struct LifterJson {
    pub ir: String,
}

pub struct Lifter {
    translator: TranslateArgs,
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
            guest_bytes,
            guest_address: address,
            config,
        })
    }

    pub fn ir(&mut self) -> Result<IRSB<'_>, TranslateError> {
        self.translator
            .front_end(self.guest_bytes.as_ptr(), self.guest_address)
    }

    pub fn process(&mut self) -> Result<LifterJson, TranslateError> {
        let ir = self.ir()?.to_string();
        Ok(LifterJson { ir })
    }
}

impl fmt::Display for Lifter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Lifter")
    }
}
