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
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use binlex::formats::{Symbol as InnerSymbol, SymbolKind as InnerSymbolKind};
use pyo3::class::basic::CompareOp;
use pyo3::prelude::*;
use pyo3::types::PyModule;
use std::hash::{Hash, Hasher};

fn hash_value<T: Hash>(value: &T) -> isize {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish() as isize
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct SymbolKind {
    pub inner: InnerSymbolKind,
}

impl SymbolKind {
    pub fn from_inner(inner: InnerSymbolKind) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl SymbolKind {
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Function: Self = Self {
        inner: InnerSymbolKind::Function,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Import: Self = Self {
        inner: InnerSymbolKind::Import,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Export: Self = Self {
        inner: InnerSymbolKind::Export,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Unknown: Self = Self {
        inner: InnerSymbolKind::Unknown,
    };

    pub fn __str__(&self) -> String {
        self.inner.to_string()
    }

    pub fn __hash__(&self) -> isize {
        hash_value(&self.inner)
    }

    pub fn __richcmp__(&self, other: PyRef<'_, Self>, op: CompareOp) -> bool {
        match op {
            CompareOp::Eq => self.inner == other.inner,
            CompareOp::Ne => self.inner != other.inner,
            _ => false,
        }
    }
}

#[pyclass(unsendable, skip_from_py_object)]
#[derive(Clone)]
pub struct Symbol {
    pub inner: InnerSymbol,
}

impl Symbol {
    pub fn from_inner(inner: InnerSymbol) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl Symbol {
    pub fn name(&self) -> String {
        self.inner.name.clone()
    }

    pub fn address(&self) -> u64 {
        self.inner.address
    }

    pub fn kind(&self) -> SymbolKind {
        SymbolKind::from_inner(self.inner.kind.clone())
    }

    pub fn __str__(&self) -> String {
        format!(
            "Symbol(name={}, address=0x{:x}, kind={})",
            self.inner.name, self.inner.address, self.inner.kind
        )
    }
}

#[pymodule]
#[pyo3(name = "symbol")]
pub fn symbol_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Symbol>()?;
    m.add_class::<SymbolKind>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.formats.symbol", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.formats.symbol")?;
    Ok(())
}
