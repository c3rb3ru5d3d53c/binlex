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

use binlex::Architecture as InnerArchitecture;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

/// Represent a supported binary architecture.
#[pyclass(eq)]
#[derive(PartialEq)]
pub struct Architecture {
    pub inner: InnerArchitecture,
}

#[pymethods]
impl Architecture {
    #[staticmethod]
    /// Construct an architecture from its numeric enum value.
    pub fn from_value(value: u16) -> Self {
        let inner = match value {
            0x00 => InnerArchitecture::AMD64,
            0x01 => InnerArchitecture::I386,
            0x02 => InnerArchitecture::ARM64,
            0x03 => InnerArchitecture::CIL,
            _ => InnerArchitecture::UNKNOWN,
        };
        Architecture { inner }
    }

    #[staticmethod]
    #[pyo3(text_signature = "(s)")]
    /// Parse an architecture from its string name.
    pub fn from_string(s: String) -> PyResult<Self> {
        let inner = InnerArchitecture::from_string(&s).map_err(|err| {
            PyValueError::new_err(format!(
                "invalid or unsupported binary architecture: {}",
                err
            ))
        })?;
        Ok(Architecture { inner })
    }

    /// Return the architecture name when converted to a string.
    pub fn __str__(&self) -> String {
        self.inner.to_string()
    }

    #[getter]
    /// Return the numeric enum value for the architecture.
    pub fn get_value(&self) -> u16 {
        self.inner as u16
    }
}

#[pymodule]
#[pyo3(name = "architecture")]
pub fn architecture_init(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Architecture>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.core.architecture", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.core.architecture")?;
    Ok(())
}
