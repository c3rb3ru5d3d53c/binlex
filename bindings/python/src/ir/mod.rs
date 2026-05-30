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

pub mod ast;
pub mod hir;
pub mod lir;
pub mod llvm;
pub mod mir;
#[cfg(not(target_os = "windows"))]
pub mod vex;

use crate::ir::ast::ast_init;
use crate::ir::llvm::llvm_init;
#[cfg(not(target_os = "windows"))]
use crate::ir::vex::vex_init;
use pyo3::prelude::*;
use pyo3::types::PyModule;
use pyo3::wrap_pymodule;

#[pymodule(name = "ir")]
pub fn ir_init(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_wrapped(wrap_pymodule!(hir::hir_init))?;
    m.add_wrapped(wrap_pymodule!(ast_init))?;
    m.add_wrapped(wrap_pymodule!(lir::lir_init))?;
    m.add_wrapped(wrap_pymodule!(mir::mir_init))?;
    m.add_wrapped(wrap_pymodule!(llvm_init))?;
    #[cfg(not(target_os = "windows"))]
    m.add_wrapped(wrap_pymodule!(vex_init))?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.ir", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.ir")?;
    Ok(())
}
