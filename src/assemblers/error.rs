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

use crate::Architecture;
use llvm_asm::Error as LlvmAsmError;
use std::error::Error as StdError;
use std::fmt;

#[derive(Debug)]
pub enum AssemblerError {
    UnsupportedArchitecture(Architecture),
    UnsupportedBackend {
        backend: &'static str,
        architecture: Architecture,
    },
    AssembleFailed(String),
    ObjectParseFailed(String),
    Internal(String),
}

impl fmt::Display for AssemblerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedArchitecture(architecture) => {
                write!(f, "unsupported assembler architecture: {}", architecture)
            }
            Self::UnsupportedBackend {
                backend,
                architecture,
            } => {
                write!(
                    f,
                    "assembler backend {} does not support architecture {}",
                    backend, architecture
                )
            }
            Self::AssembleFailed(message) => write!(f, "assembly failed: {}", message),
            Self::ObjectParseFailed(message) => write!(f, "object parse failed: {}", message),
            Self::Internal(message) => write!(f, "assembler internal error: {}", message),
        }
    }
}

impl StdError for AssemblerError {}

impl From<LlvmAsmError> for AssemblerError {
    fn from(value: LlvmAsmError) -> Self {
        match value {
            LlvmAsmError::UnsupportedArchitecture(_) => {
                Self::Internal("llvm-asm rejected an architecture mapping".to_string())
            }
            LlvmAsmError::AssembleFailed(message) => Self::AssembleFailed(message),
            LlvmAsmError::ObjectParseFailed(message) => Self::ObjectParseFailed(message),
            LlvmAsmError::Internal(message) => Self::Internal(message),
        }
    }
}
