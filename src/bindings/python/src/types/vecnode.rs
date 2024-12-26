pub use binlex::types::VecNode as InnerVecNode;
use std::sync::{Arc, Mutex};
use pyo3::prelude::*;

#[pyclass]
pub struct VecNode {
    pub inner: Arc<Mutex<InnerVecNode>>,
}

#[pymethods]
impl VecNode {
    #[new]
    #[pyo3(text_signature = "(id)")]
    pub fn new(id: u64) -> Self {
        let inner = InnerVecNode::new(id);
        Self {
            inner: Arc::new(Mutex::new(inner))
        }
    }

    #[pyo3(text_signature = "($self, child)")]
    pub fn add_child(&self, py: Python, child: Py<VecNode>) {
        let inner_child = child.borrow(py).inner.lock().unwrap().clone();
        self.inner.lock().unwrap().add_child(inner_child);
    }

    #[pyo3(text_signature = "($self, parent)")]
    pub fn add_parent(&self, py: Python, parent: Py<VecNode>) {
        let inner_parent = parent.borrow(py).inner.lock().unwrap().clone();
        self.inner.lock().unwrap().add_parent(inner_parent);
    }

    #[pyo3(text_signature = "($self)")]
    pub fn children(&self) -> Vec<VecNode> {
        let mut result = Vec::<VecNode>::new();
        for child in self.inner.lock().unwrap().children() {
            let a = VecNode {
                inner: Arc::new(Mutex::new(child.clone()))
            };
            result.push(a);
        }
        result
    }

    #[pyo3(text_signature = "($self)")]
    pub fn parents(&self) -> Vec<VecNode> {
        let mut result = Vec::<VecNode>::new();
        for parent in self.inner.lock().unwrap().parents() {
            let a = VecNode {
                inner: Arc::new(Mutex::new(parent.clone()))
            };
            result.push(a);
        }
        result
    }

    #[pyo3(text_signature = "($self, key, value)")]
    pub fn add_property(&mut self, key: String, value: f64) {
        self.inner
            .lock()
            .unwrap()
            .add_property(&key, value)
    }

    #[pyo3(text_signature = "($self, key, values)")]
    pub fn add_properties(&mut self, key: String, values: Vec<f64>) {
        self.inner
            .lock()
            .unwrap()
            .add_properties(&key, values)
    }

    #[pyo3(text_signature = "($self)")]
    pub fn print(&self) {
        self.inner
            .lock()
            .unwrap()
            .print()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn to_vec(&self) -> Vec<f64> {
        self.inner
            .lock()
            .unwrap()
            .to_vec()
    }
}

#[pymodule]
#[pyo3(name = "vecnode")]
pub fn vecnode_init(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<VecNode>()?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("binlex.types.vecnode", m)?;
    m.setattr("__name__", "binlex.types.vecnode")?;
    Ok(())
}
