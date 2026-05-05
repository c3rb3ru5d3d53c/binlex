use crate::controlflow::{Block, Function, Instruction};
use crate::{Architecture, Configuration};
use binlex::embeddings::{Embedding as InnerEmbedding, EmbeddingBackend as InnerEmbeddingBackend};
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;

fn parse_backend(
    py: Python<'_>,
    value: Option<Py<PyAny>>,
) -> PyResult<Option<InnerEmbeddingBackend>> {
    let Some(value) = value else {
        return Ok(None);
    };

    let value = value.bind(py);
    let backend_value = value
        .getattr("value")
        .map_err(|_| PyTypeError::new_err("backend must be an EmbeddingBackend"))?;
    let backend_value: String = backend_value.extract()?;

    match backend_value.trim().to_ascii_lowercase().as_str() {
        "default" => Ok(Some(InnerEmbeddingBackend::Default)),
        "llvm" => Ok(Some(InnerEmbeddingBackend::Llvm)),
        "vex" => Ok(Some(InnerEmbeddingBackend::Vex)),
        other => Err(PyValueError::new_err(format!(
            "unsupported embedding backend: {other}"
        ))),
    }
}

#[pyclass]
pub struct Embedding {
    inner: InnerEmbedding,
}

#[pymethods]
impl Embedding {
    #[new]
    #[pyo3(signature = (architecture, configuration, backend=None, dimensions=None), text_signature = "(architecture, configuration, backend=None, dimensions=None)")]
    pub fn new(
        py: Python<'_>,
        architecture: Py<Architecture>,
        configuration: Py<Configuration>,
        backend: Option<Py<PyAny>>,
        dimensions: Option<usize>,
    ) -> PyResult<Self> {
        let architecture = architecture.borrow(py).inner;
        let configuration = configuration.borrow(py).inner.lock().unwrap().clone();
        Ok(Self {
            inner: InnerEmbedding::new(
                architecture,
                configuration,
                parse_backend(py, backend)?,
                dimensions,
            ),
        })
    }

    #[pyo3(text_signature = "($self, instruction)")]
    pub fn embed_instruction(
        &self,
        py: Python<'_>,
        instruction: &Instruction,
    ) -> PyResult<Option<Vec<f32>>> {
        instruction.with_inner_instruction(py, |inner| Ok(self.inner.embed_instruction(inner)))
    }

    #[pyo3(text_signature = "($self, block)")]
    pub fn embed_block(&self, py: Python<'_>, block: &Block) -> PyResult<Option<Vec<f32>>> {
        block.with_inner_block(py, |inner| Ok(self.inner.embed_block(inner)))
    }

    #[pyo3(text_signature = "($self, function)")]
    pub fn embed_function(
        &self,
        py: Python<'_>,
        function: &Function,
    ) -> PyResult<Option<Vec<f32>>> {
        function.with_inner_function(py, |inner| Ok(self.inner.embed_function(inner)))
    }
}

#[pymodule]
#[pyo3(name = "embeddings")]
pub fn embeddings_init(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Embedding>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.embeddings", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.embeddings")?;
    Ok(())
}
