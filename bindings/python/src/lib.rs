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

pub mod clients;
pub mod compression;
pub mod config;
pub mod controlflow;
pub mod core;
pub mod databases;
pub mod disassemblers;
pub mod formats;
pub mod genetics;
pub mod hashing;
pub mod hex;
pub mod imaging;
pub mod indexing;
#[cfg(not(target_os = "windows"))]
pub mod lifters;
pub mod math;
pub mod metadata;
pub mod storage;
pub mod util;
pub mod yara;

pub use config::Config;
pub use core::Architecture;
pub use core::Magic;

use crate::clients::clients_init;
use crate::compression::compression_init;
use crate::config::config_module_init;
use crate::controlflow::controlflow_init;
use crate::core::core_init;
use crate::databases::databases_init;
use crate::disassemblers::disassemblers_init;
use crate::formats::formats_init;
use crate::genetics::genitics_init;
use crate::hashing::hashing_init;
use crate::hex::hex_init;
use crate::imaging::imaging_init;
use crate::indexing::indexing_init;
#[cfg(not(target_os = "windows"))]
use crate::lifters::lifters_init;
use crate::math::{entropy_init, math_init};
use crate::metadata::metadata_init;
use crate::storage::storage_init;
use crate::util::util_init;
use crate::yara::yara_init;
use ::binlex::runtime::{register_host_runtime, HostRuntime};

use pyo3::{prelude::*, types::PyModule, wrap_pymodule};

#[pymodule]
fn binlex(m: &Bound<'_, PyModule>) -> PyResult<()> {
    register_host_runtime(HostRuntime::Native).map_err(
        |error: ::binlex::runtime::HostRuntimeError| {
            pyo3::exceptions::PyRuntimeError::new_err(error.to_string())
        },
    )?;

    m.add_wrapped(wrap_pymodule!(clients_init))?;
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
    m.add_wrapped(wrap_pymodule!(genitics_init))?;
    m.add_wrapped(wrap_pymodule!(hashing_init))?;
    m.add_wrapped(wrap_pymodule!(imaging_init))?;
    m.add_wrapped(wrap_pymodule!(indexing_init))?;
    m.add_wrapped(wrap_pymodule!(databases_init))?;
    #[cfg(not(target_os = "windows"))]
    m.add_wrapped(wrap_pymodule!(lifters_init))?;
    m.add_class::<Architecture>()?;
    m.add_class::<Config>()?;
    m.add_class::<Magic>()?;
    m.add_wrapped(wrap_pymodule!(util_init))?;
    m.add_wrapped(wrap_pymodule!(storage_init))?;
    m.add_wrapped(wrap_pymodule!(yara_init))?;
    Ok(())
}
