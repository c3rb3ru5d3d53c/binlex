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

pub mod formats;
pub mod types;
pub mod global;
pub mod hashing;
pub mod binary;
pub mod disassemblers;
pub mod controlflow;
pub mod genetics;
pub mod imaging;

pub use binary::Binary;
pub use global::Config;
pub use global::Architecture;

use crate::formats::formats_init;
use crate::types::types_init;
use crate::binary::binary_init;
use crate::disassemblers::disassemblers_init;
use crate::controlflow::controlflow_init;
use crate::genetics::genitics_init;
use crate::global::global_init;
use crate::hashing::hashing_init;
use crate::imaging::imaging_init;

use pyo3::{prelude::*, wrap_pymodule};

#[pymodule]
fn binlex(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_wrapped(wrap_pymodule!(formats_init))?;
    m.add_wrapped(wrap_pymodule!(controlflow_init))?;
    m.add_wrapped(wrap_pymodule!(types_init))?;
    m.add_wrapped(wrap_pymodule!(global_init))?;
    m.add_wrapped(wrap_pymodule!(binary_init))?;
    m.add_wrapped(wrap_pymodule!(disassemblers_init))?;
    m.add_wrapped(wrap_pymodule!(genitics_init))?;
    m.add_wrapped(wrap_pymodule!(hashing_init))?;
    m.add_wrapped(wrap_pymodule!(imaging_init))?;
    m.add_class::<Binary>()?;
    m.add_class::<Architecture>()?;
    m.add_class::<Config>()?;
    Ok(())
}
