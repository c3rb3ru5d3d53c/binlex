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

use super::error::AssemblerError;
use crate::Architecture;
use llvm_asm::{Architecture as LlvmArchitecture, Assembler as LlvmAssembler};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AssemblerBackend {
    Default,
    LLVM,
}

pub(crate) enum ResolvedAssemblerBackend {
    LLVM(LlvmAssembler),
}

impl ResolvedAssemblerBackend {
    pub(crate) fn new(
        architecture: Architecture,
        backend: AssemblerBackend,
    ) -> Result<Self, AssemblerError> {
        let architecture = map_architecture(architecture)?;
        match backend {
            AssemblerBackend::Default | AssemblerBackend::LLVM => {
                Ok(Self::LLVM(LlvmAssembler::new(architecture)?))
            }
        }
    }

    pub(crate) fn assemble(&self, address: u64, text: &str) -> Result<Vec<u8>, AssemblerError> {
        match self {
            Self::LLVM(assembler) => Ok(assembler.assemble(address, text)?),
        }
    }
}

fn map_architecture(architecture: Architecture) -> Result<LlvmArchitecture, AssemblerError> {
    match architecture {
        Architecture::AMD64 => Ok(LlvmArchitecture::AMD64),
        Architecture::I386 => Ok(LlvmArchitecture::I386),
        Architecture::ARM64 => Ok(LlvmArchitecture::ARM64),
        _ => Err(AssemblerError::UnsupportedArchitecture(architecture)),
    }
}
