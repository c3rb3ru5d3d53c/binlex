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

use std::fmt;
use std::io::Error;
use std::io::ErrorKind;
use std::str::FromStr;

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
    UNKNOWN = 0x03,
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

    pub fn from_string(s: &str) -> Result<Self, Error> {
        match s.to_lowercase().as_str() {
            "amd64" => Ok(Architecture::AMD64),
            "i386" => Ok(Architecture::I386),
            "cil" => Ok(Architecture::CIL),
            _ => Err(Error::new(
                ErrorKind::InvalidInput,
                format!("invalid or unsupported architecture: {}", s),
            )),
        }
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
            _ => Err(Error::new(
                ErrorKind::InvalidInput,
                format!("invalid or unsupported architecture: {}", s),
            )
            .to_string()),
        }
    }
}
