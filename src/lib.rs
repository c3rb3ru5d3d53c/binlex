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

pub mod assemblers;
pub mod compression;
pub mod config;
pub mod controlflow;
pub mod core;
pub mod decompilers;
pub mod disassemblers;
pub mod embeddings;
pub mod formats;
pub mod genetics;
pub mod hashing;
pub mod hex;
pub mod io;
pub mod irs;
pub mod math;
pub mod metadata;
pub mod rules;
pub mod utilities;

pub use assemblers::Assembler;
pub use assemblers::AssemblerBackend;
pub use assemblers::AssemblerError;
pub use config::AUTHOR;
pub use config::Configuration;
pub use config::VERSION;
pub use core::Architecture;
pub use core::Magic;
pub use core::OperatingSystem;
pub use core::Transport;
pub use decompilers::DecompiledFunction;
pub use decompilers::Decompiler;
pub use decompilers::DecompilerBackend;
pub use disassemblers::Disassembler;
pub use disassemblers::DisassemblerBackend;
pub use embeddings::Embedding;
pub use embeddings::EmbeddingBackend;
pub use irs::lir::{
    LirCpuAmd64, LirCpuArm64, LirCpuCil, LirCpuI386, LirCpuKind, LirExecutor, LirExecutorState,
};
pub use math::entropy;
