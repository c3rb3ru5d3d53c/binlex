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

pub mod block;
pub mod function;
pub mod graph;
pub mod instruction;
pub mod reference;

pub use crate::controlflow::block::Block;
pub use crate::controlflow::block::BlockJsonDeserializer;
pub use crate::controlflow::function::Function;
pub use crate::controlflow::function::FunctionJsonDeserializer;
pub use crate::controlflow::graph::Graph;
pub use crate::controlflow::graph::GraphQueue;
pub use crate::controlflow::instruction::Instruction;
pub use crate::controlflow::instruction::InstructionJsonDeserializer;
pub use crate::controlflow::reference::Reference;

use crate::controlflow::block::block_init;
use crate::controlflow::function::function_init;
use crate::controlflow::graph::graph_init;
use crate::controlflow::instruction::instruction_init;
use crate::controlflow::reference::Reference as PyReference;

use binlex::controlflow::EntityKind as InnerEntityKind;
use pyo3::class::basic::CompareOp;
use pyo3::{prelude::*, wrap_pymodule};
use serde_json::Value;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

fn hash_value<T: Hash>(value: &T) -> isize {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish() as isize
}

pub(crate) fn json_value_to_py(py: Python<'_>, value: &Value) -> PyResult<Py<PyAny>> {
    let json_str = serde_json::to_string(value)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;
    let json_module = py.import("json")?;
    Ok(json_module.call_method1("loads", (json_str,))?.into())
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct EntityKind {
    pub inner: InnerEntityKind,
}

impl EntityKind {
    pub fn from_inner(inner: InnerEntityKind) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl EntityKind {
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Instruction: Self = Self {
        inner: InnerEntityKind::Instruction,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Block: Self = Self {
        inner: InnerEntityKind::Block,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Function: Self = Self {
        inner: InnerEntityKind::Function,
    };

    pub fn __str__(&self) -> String {
        format!("{:?}", self.inner)
    }

    pub fn __hash__(&self) -> isize {
        hash_value(&self.inner)
    }

    pub fn __richcmp__(&self, other: PyRef<'_, Self>, op: CompareOp) -> bool {
        match op {
            CompareOp::Eq => self.inner == other.inner,
            CompareOp::Ne => self.inner != other.inner,
            CompareOp::Lt => self.inner < other.inner,
            CompareOp::Le => self.inner <= other.inner,
            CompareOp::Gt => self.inner > other.inner,
            CompareOp::Ge => self.inner >= other.inner,
        }
    }
}

#[pymodule]
#[pyo3(name = "controlflow")]
pub fn controlflow_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_wrapped(wrap_pymodule!(graph_init))?;
    m.add_wrapped(wrap_pymodule!(instruction_init))?;
    m.add_wrapped(wrap_pymodule!(block_init))?;
    m.add_wrapped(wrap_pymodule!(function_init))?;
    m.add_class::<Graph>()?;
    m.add_class::<GraphQueue>()?;
    m.add_class::<EntityKind>()?;
    m.add_class::<Instruction>()?;
    m.add_class::<InstructionJsonDeserializer>()?;
    m.add_class::<PyReference>()?;
    m.add_class::<Block>()?;
    m.add_class::<BlockJsonDeserializer>()?;
    m.add_class::<Function>()?;
    m.add_class::<FunctionJsonDeserializer>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.controlflow", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.controlflow")?;
    Ok(())
}
