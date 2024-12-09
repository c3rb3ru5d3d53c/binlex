use std::str::FromStr;
use std::fmt;

/// Represents the different architectures of a binary.
#[repr(u16)]
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum Architecture {
    /// 64-bit AMD architecture.
    AMD64 = 0x00,
    /// 32-bit Intel architecture.
    I386 = 0x01,
    /// CIL
    CIL = 0x02,
    /// Unknown architecture.
    UNKNOWN= 0x03,
}

impl Architecture {
    pub fn to_vec() -> Vec<String> {
        vec![
            Architecture::AMD64.to_string(),
            Architecture::I386.to_string(),
            Architecture::CIL.to_string(),
        ]
    }
}

impl Architecture {
    pub fn to_list() -> String {
        Architecture::to_vec().join(", ")
    }
}

/// Implements Display for `BinaryArchitecture` enum
impl fmt::Display for Architecture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let architecture = match self {
            Architecture::AMD64 => "amd64",
            Architecture::I386 => "i386",
            Architecture::CIL => "cil",
            Architecture::UNKNOWN => "unknown",
        };
        write!(f, "{}", architecture)
    }
}

impl FromStr for Architecture {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "amd64" => Ok(Architecture::AMD64),
            "i386" => Ok(Architecture::I386),
            "cil" => Ok(Architecture::CIL),
            _ => Err(format!("invalid architecutre")),
        }
    }
}
