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

pub mod file;
pub mod pe;
pub mod elf;
pub mod macho;

use crate::formats::file::file_init;
use crate::formats::pe::pe_init;
use crate::formats::macho::macho_init;

pub use crate::formats::pe::PE;
pub use crate::formats::file::File;
pub use crate::formats::elf::ELF;
pub use crate::formats::macho::MACHO;

use pyo3::{prelude::*, wrap_pymodule};

#[pymodule]
#[pyo3(name = "formats")]
pub fn formats_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_wrapped(wrap_pymodule!(file_init))?;
    m.add_wrapped(wrap_pymodule!(pe_init))?;
    m.add_wrapped(wrap_pymodule!(macho_init))?;
    m.add_class::<PE>()?;
    m.add_class::<File>()?;
    m.add_class::<ELF>()?;
    m.add_class::<MACHO>()?;
     py.import_bound("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.formats", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.formats")?;
    Ok(())
}
