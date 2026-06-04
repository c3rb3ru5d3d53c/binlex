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
pub mod imaging;
pub mod irs;
pub mod math;
pub mod metadata;
pub mod rules;
pub mod utilities;

pub use config::Configuration;
pub use core::Architecture;
pub use core::Magic;

use crate::assemblers::assemblers_init;
use crate::compression::compression_init;
use crate::config::config_module_init;
use crate::controlflow::controlflow_init;
use crate::core::core_init;
use crate::decompilers::decompilers_init;
use crate::disassemblers::disassemblers_init;
use crate::embeddings::embeddings_init;
use crate::formats::formats_init;
use crate::genetics::genitics_init;
use crate::hashing::hashing_init;
use crate::hex::hex_init;
use crate::imaging::imaging_init;
use crate::irs::irs_init;
use crate::math::{entropy_init, math_init};
use crate::metadata::metadata_init;
use crate::rules::rules_init;
use crate::utilities::utilities_init;

use pyo3::{prelude::*, types::PyModule, wrap_pymodule};

#[pymodule]
fn binlex(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_wrapped(wrap_pymodule!(assemblers_init))?;
    m.add_wrapped(wrap_pymodule!(compression_init))?;
    m.add_wrapped(wrap_pymodule!(formats_init))?;
    m.add_wrapped(wrap_pymodule!(controlflow_init))?;
    m.add_wrapped(wrap_pymodule!(config_module_init))?;
    m.add_wrapped(wrap_pymodule!(core_init))?;
    m.add_wrapped(wrap_pymodule!(hex_init))?;
    m.add_wrapped(wrap_pymodule!(entropy_init))?;
    m.add_wrapped(wrap_pymodule!(math_init))?;
    m.add_wrapped(wrap_pymodule!(metadata_init))?;
    m.add_wrapped(wrap_pymodule!(disassemblers_init))?;
    m.add_wrapped(wrap_pymodule!(embeddings_init))?;
    m.add_wrapped(wrap_pymodule!(genitics_init))?;
    m.add_wrapped(wrap_pymodule!(hashing_init))?;
    m.add_wrapped(wrap_pymodule!(imaging_init))?;
    m.add_wrapped(wrap_pymodule!(decompilers_init))?;
    m.add_wrapped(wrap_pymodule!(irs_init))?;
    m.add_class::<Architecture>()?;
    m.add_class::<Configuration>()?;
    m.add_class::<Magic>()?;
    m.add_wrapped(wrap_pymodule!(utilities_init))?;
    m.add_wrapped(wrap_pymodule!(rules_init))?;
    Ok(())
}
