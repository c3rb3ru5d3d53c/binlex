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

pub use crate::controlflow::block::Block;
pub use crate::controlflow::block::BlockJsonDeserializer;
pub use crate::controlflow::function::Function;
pub use crate::controlflow::function::FunctionJsonDeserializer;
pub use crate::controlflow::graph::Graph;
pub use crate::controlflow::graph::GraphQueue;
pub use crate::controlflow::instruction::Instruction;

use crate::controlflow::block::block_init;
use crate::controlflow::function::function_init;
use crate::controlflow::graph::graph_init;
use crate::controlflow::instruction::instruction_init;

use pyo3::{prelude::*, wrap_pymodule};
use serde_json::Value;

pub(crate) fn json_value_to_py(py: Python<'_>, value: &Value) -> PyResult<Py<PyAny>> {
    let json_str = serde_json::to_string(value)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;
    let json_module = py.import("json")?;
    Ok(json_module.call_method1("loads", (json_str,))?.into())
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
    m.add_class::<Instruction>()?;
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
