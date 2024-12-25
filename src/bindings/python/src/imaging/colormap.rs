use pyo3::prelude::*;
use binlex::imaging::colormap::ColorMap as InnerColorMap;
use binlex::imaging::colormap::ColorMapType as InnerColorMapType;
use std::sync::Arc;
use std::sync::Mutex;
use pyo3::exceptions::PyRuntimeError;
use pyo3::types::PyBytes;

#[pyclass]
pub struct ColorMapType {
    inner: Arc<Mutex<InnerColorMapType>>,
}

#[pymethods]
impl ColorMapType {
    #[staticmethod]
    pub fn from_string(string: String) -> PyResult<Self> {
        let inner = InnerColorMapType::from_string(&string).map_err(|e| PyErr::new::<PyRuntimeError, _>(e.to_string()))?;
        Ok(Self {
            inner: Arc::new(Mutex::new(inner))
        })
    }
}

#[pyclass]
pub struct ColorMap {
    inner: Arc<Mutex<InnerColorMap>>,
}

#[pymethods]
impl ColorMap {
    #[new]
    #[pyo3(text_signature = "()")]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(InnerColorMap::new()))
        }
    }

    #[pyo3(text_signature = "($self, color_map_type)")]
    pub fn set_color_map_type(&mut self, py: Python, color_map_type: Py<ColorMapType>) {
        let inner_color_map_type = color_map_type
            .borrow(py)
            .inner
            .lock()
            .unwrap()
            .clone();
        self.inner
            .lock()
            .unwrap()
            .set_color_map_type(inner_color_map_type);
    }

    #[pyo3(signature = (data, offset=0))]
    pub fn append(&mut self, py: Python, data: Py<PyBytes>, offset: u64) {
        let inner_data = data.bind(py).as_bytes();
        self.inner.lock().unwrap().append(offset, inner_data);
    }

    #[pyo3(text_signature = "($self, cell_size)")]
    pub fn set_cell_size(&mut self, cell_size: usize) {
        self.inner.lock().unwrap().set_cell_size(cell_size)
    }

    #[pyo3(text_signature = "($self, fixed_width)")]
    pub fn set_fixed_width(&mut self, fixed_width: usize) {
        self.inner.lock().unwrap().set_fixed_width(fixed_width);
    }

    #[pyo3(text_signature = "($self, key, value)")]
    pub fn insert_metadata(&mut self, key: String, value: String) {
        self.inner.lock().unwrap().insert_metadata(key, value)
    }

    #[pyo3(text_signature = "($self)")]
    pub fn to_svg_string(&self) -> String {
        self.inner.lock().unwrap().to_svg_string()
    }

    #[pyo3(text_signature = "($self, file_path)")]
    pub fn write(&self, file_path: String) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .write(&file_path)
            .map_err(|e| PyErr::new::<PyRuntimeError, _>(e.to_string()))
    }
}

#[pymodule]
#[pyo3(name = "colormap")]
pub fn colormap_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<ColorMap>()?;
    m.add_class::<ColorMapType>()?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("binlex.imaging.colormap", m)?;
    m.setattr("__name__", "binlex.imaging.colormap")?;
    Ok(())
}