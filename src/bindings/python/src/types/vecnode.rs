pub use binlex::types::VecNode as InnerVecNode;
pub use binlex::types::VecGraph as InnerVecGraph;
use std::sync::{Arc, Mutex};
use pyo3::prelude::*;

#[pyclass]
pub struct VecGraph {
    pub inner: Arc<Mutex<InnerVecGraph>>,
}

#[pymethods]
impl VecGraph {
    #[new]
    #[pyo3(text_signature = "()")]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(InnerVecGraph::new()))
        }
    }

    #[pyo3(text_signature = "($self, node)")]
    pub fn insert_node(&mut self, py: Python, node: Py<VecNode>) {
        let inner_node = node
            .borrow(py)
            .inner.lock()
            .unwrap()
            .clone();
        self.inner.lock().unwrap().insert_node(inner_node);
    }

    #[pyo3(text_signature = "($self, id)")]
    pub fn get_node(&self, id: u64) -> Option<VecNode> {
        let binding = self.inner.lock().unwrap();
        let inner_node = binding.get_node(id)?;
        let node = VecNode {
            inner: Arc::new(Mutex::new(inner_node.clone()))
        };
        Some(node)
    }

    #[pyo3(text_signature = "($self, node1_id, node2_id)")]
    pub fn add_relationship(&mut self, node1_id: u64, node2_id: u64) {
        let mut binding = self.inner
            .lock()
            .unwrap();
        binding.add_relationship(node1_id, node2_id)
    }

    #[pyo3(text_signature = "($self)")]
    pub fn to_vec(&self) -> Vec<f64> {
        self.inner.lock().unwrap().to_vec()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn print(&self) {
        self.inner
            .lock()
            .unwrap()
            .print()
    }

}

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

    #[pyo3(text_signature = "($self)")]
    pub fn id(&self) -> u64 {
        self.inner.lock().unwrap().id()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn relationships(&self) -> Vec<u64> {
        self.inner
            .lock()
            .unwrap()
            .relationships()
            .clone()
    }

    pub fn add_relationship(&self, id: u64) {
        self.inner
            .lock()
            .unwrap()
            .add_relationship(id)
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
}

#[pymodule]
#[pyo3(name = "vecnode")]
pub fn vecnode_init(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<VecNode>()?;
    m.add_class::<VecGraph>()?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("binlex.types.vecnode", m)?;
    m.setattr("__name__", "binlex.types.vecnode")?;
    Ok(())
}
