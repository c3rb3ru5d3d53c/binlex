pub mod graph;
pub mod instruction;
pub mod block;
pub mod function;

pub use crate::controlflow::graph::Graph;
pub use crate::controlflow::graph::GraphQueue;
pub use crate::controlflow::block::Block;
pub use crate::controlflow::function::Function;
pub use crate::controlflow::instruction::Instruction;

use crate::controlflow::graph::graph_init;
use crate::controlflow::instruction::instruction_init;
use crate::controlflow::block::block_init;
use crate::controlflow::function::function_init;

use pyo3::{prelude::*, wrap_pymodule};

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
    m.add_class::<Function>()?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("binlex.controlflow", m)?;
    m.setattr("__name__", "binlex.controlflow")?;
    Ok(())
}
