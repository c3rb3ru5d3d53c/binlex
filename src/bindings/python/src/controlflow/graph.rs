use pyo3::prelude::*;
use std::collections::BTreeSet;
use binlex::controlflow::GraphQueue as InnerGraphQueue;
use binlex::controlflow::Graph as InnerGraph;
use crate::Architecture;
use crate::config::Config;
use std::sync::Arc;
use std::sync::Mutex;

#[pyclass]
pub struct GraphQueue {
    inner_graph: Arc<Mutex<InnerGraph>>,
    kind: QueueKind,
}

#[derive(Clone, Copy)]
enum QueueKind {
    Instructions,
    Blocks,
    Functions,
}

impl GraphQueue {
    fn get_queue<'a>(&self, inner: &'a InnerGraph) -> &'a InnerGraphQueue {
        match self.kind {
            QueueKind::Instructions => &inner.instructions,
            QueueKind::Blocks => &inner.blocks,
            QueueKind::Functions => &inner.functions,
        }
    }

    fn get_queue_mut<'a>(&self, inner: &'a mut InnerGraph) -> &'a mut InnerGraphQueue {
        match self.kind {
            QueueKind::Instructions => &mut inner.instructions,
            QueueKind::Blocks => &mut inner.blocks,
            QueueKind::Functions => &mut inner.functions,
        }
    }
}

#[pymethods]
impl GraphQueue {
    #[pyo3(text_signature = "($self, address)")]
    pub fn insert_invalid(&self, address: u64) {
        let mut inner = self.inner_graph.lock().unwrap();
        self.get_queue_mut(&mut inner).insert_invalid(address);
    }

    #[pyo3(text_signature = "($self, address)")]
    pub fn is_invalid(&self, address: u64) -> bool {
        let inner = self.inner_graph.lock().unwrap();
        self.get_queue(&inner).is_invalid(address)
    }

    #[pyo3(text_signature = "($self)")]
    pub fn valid_addresses(&self) -> BTreeSet<u64> {
        let inner = self.inner_graph.lock().unwrap();
        self.get_queue(&inner).valid_addresses()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn invalid_addresses(&self) -> BTreeSet<u64> {
        let inner = self.inner_graph.lock().unwrap();
        self.get_queue(&inner).invalid_addresses()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn processed_addresses(&self) -> BTreeSet<u64> {
        let inner = self.inner_graph.lock().unwrap();
        self.get_queue(&inner).processed_addresses()
    }

    #[pyo3(text_signature = "($self, address)")]
    pub fn is_valid(&self, address: u64) -> bool {
        let inner = self.inner_graph.lock().unwrap();
        self.get_queue(&inner).is_valid(address)
    }

    #[pyo3(text_signature = "($self, address)")]
    pub fn insert_valid(&self, address: u64) {
        let mut inner = self.inner_graph.lock().unwrap();
        self.get_queue_mut(&mut inner).insert_valid(address);
    }

    #[pyo3(text_signature = "($self, addresses)")]
    pub fn insert_processed_extend(&self, addresses: BTreeSet<u64>) {
        let mut inner = self.inner_graph.lock().unwrap();
        self.get_queue_mut(&mut inner).insert_processed_extend(addresses);
    }

    #[pyo3(text_signature = "($self, address)")]
    pub fn insert_processed(&self, address: u64) {
        let mut inner = self.inner_graph.lock().unwrap();
        self.get_queue_mut(&mut inner).insert_processed(address);
    }

    #[pyo3(text_signature = "($self, address)")]
    pub fn is_processed(&self, address: u64) -> bool {
        let inner = self.inner_graph.lock().unwrap();
        self.get_queue(&inner).is_processed(address)
    }

    #[pyo3(text_signature = "($self, addresses)")]
    pub fn enqueue_extend(&self, addresses: BTreeSet<u64>) {
        let mut inner = self.inner_graph.lock().unwrap();
        self.get_queue_mut(&mut inner).enqueue_extend(addresses);
    }

    #[pyo3(text_signature = "($self, address)")]
    pub fn enqueue(&self, address: u64) -> bool {
        let mut inner = self.inner_graph.lock().unwrap();
        self.get_queue_mut(&mut inner).enqueue(address)
    }

    #[pyo3(text_signature = "($self)")]
    pub fn dequeue(&self) -> Option<u64> {
        let mut inner = self.inner_graph.lock().unwrap();
        self.get_queue_mut(&mut inner).dequeue()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn dequeue_all(&self) -> BTreeSet<u64> {
        let mut inner = self.inner_graph.lock().unwrap();
        self.get_queue_mut(&mut inner).dequeue_all()
    }
}

#[pyclass]
pub struct Graph {
    pub inner: Arc<Mutex<InnerGraph>>,
}

#[pymethods]
impl Graph {
    #[new]
    #[pyo3(text_signature = "(architecture, config)")]
    pub fn new(py: Python, architecture: Py<Architecture>, config: Py<Config>) -> Self {
        let inner_config = config.borrow(py).inner.lock().unwrap().clone();
        let inner = InnerGraph::new(architecture.borrow(py).inner, inner_config);
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }

    #[getter]
    pub fn get_instructions(&self, py: Python) -> Py<GraphQueue> {
        Py::new(
            py,
            GraphQueue {
                inner_graph: Arc::clone(&self.inner),
                kind: QueueKind::Instructions,
            },
        )
        .expect("failed to get instructions graph queue")
    }

    #[getter]
    pub fn get_blocks(&self, py: Python) -> Py<GraphQueue> {
        Py::new(
            py,
            GraphQueue {
                inner_graph: Arc::clone(&self.inner),
                kind: QueueKind::Blocks,
            },
        )
        .expect("failed to get blocks graph queue")
    }

    #[getter]
    pub fn get_functions(&self, py: Python) -> Py<GraphQueue> {
        Py::new(
            py,
            GraphQueue {
                inner_graph: Arc::clone(&self.inner),
                kind: QueueKind::Functions,
            },
        )
        .expect("failed to get functions graph queue")
    }

    #[pyo3(text_signature = "($self, cfg)")]
    pub fn absorb(&mut self, py: Python, cfg: Py<Self>) {
        self.inner
            .lock()
            .unwrap()
            .absorb(&mut cfg.borrow_mut(py).inner.lock().unwrap());
    }
}

#[pymodule]
#[pyo3(name = "graph")]
pub fn graph_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<GraphQueue>()?;
    m.add_class::<Graph>()?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("binlex.controlflow.graph", m)?;
    m.setattr("__name__", "binlex.controlflow.graph")?;
    Ok(())
}
