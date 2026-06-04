use ::binlex::metadata::SymbolType as InnerSymbolType;
use pyo3::prelude::*;

#[pyclass(eq, skip_from_py_object)]
#[derive(Clone, PartialEq)]
pub struct SymbolType {
    pub inner: InnerSymbolType,
}

#[pymethods]
impl SymbolType {
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Instruction: Self = Self {
        inner: InnerSymbolType::Instruction,
    };

    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Block: Self = Self {
        inner: InnerSymbolType::Block,
    };

    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Function: Self = Self {
        inner: InnerSymbolType::Function,
    };

    pub fn __str__(&self) -> String {
        self.inner.to_string()
    }
}

#[pymodule]
#[pyo3(name = "metadata")]
pub fn metadata_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<SymbolType>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.metadata", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.metadata")?;
    Ok(())
}
