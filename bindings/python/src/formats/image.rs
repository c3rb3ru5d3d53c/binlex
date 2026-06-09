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
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use binlex::formats::Image as InnerImage;
use binlex::formats::ImagePermissions as InnerImagePermissions;
use binlex::formats::ImageSegment as InnerImageSegment;
use pyo3::exceptions::{PyIndexError, PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes, PyModule};
use serde_json::Value;
use std::collections::BTreeMap;

fn json_value_to_py(py: Python<'_>, value: &Value) -> PyResult<Py<PyAny>> {
    let json_str =
        serde_json::to_string(value).map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
    let json_module = py.import("json")?;
    Ok(json_module.call_method1("loads", (json_str,))?.into())
}

fn py_to_json_value(py: Python<'_>, value: Py<PyAny>) -> PyResult<Value> {
    let json_module = py.import("json")?;
    let json_str = json_module
        .call_method1("dumps", (value,))?
        .extract::<String>()?;
    serde_json::from_str(&json_str).map_err(|error| PyValueError::new_err(error.to_string()))
}

/// Virtual image segment permissions.
#[pyclass]
pub struct ImagePermissions {
    pub inner: InnerImagePermissions,
}

#[pymethods]
impl ImagePermissions {
    #[new]
    #[pyo3(text_signature = "(read=True, write=False, execute=False)")]
    pub fn new(read: Option<bool>, write: Option<bool>, execute: Option<bool>) -> Self {
        Self {
            inner: InnerImagePermissions::new(
                read.unwrap_or(true),
                write.unwrap_or(false),
                execute.unwrap_or(false),
            ),
        }
    }

    #[staticmethod]
    #[pyo3(text_signature = "()")]
    pub fn readable() -> Self {
        Self {
            inner: InnerImagePermissions::readable(),
        }
    }

    #[staticmethod]
    #[pyo3(text_signature = "()")]
    pub fn executable() -> Self {
        Self {
            inner: InnerImagePermissions::executable(),
        }
    }

    #[getter]
    pub fn read(&self) -> bool {
        self.inner.read
    }

    #[getter]
    pub fn write(&self) -> bool {
        self.inner.write
    }

    #[getter]
    pub fn execute(&self) -> bool {
        self.inner.execute
    }
}

/// Virtual image segment.
#[pyclass]
pub struct ImageSegment {
    pub inner: InnerImageSegment,
}

#[pymethods]
impl ImageSegment {
    #[staticmethod]
    #[pyo3(text_signature = "(name, virtual_address, data, permissions)")]
    pub fn bytes(
        name: Option<String>,
        virtual_address: u64,
        data: Vec<u8>,
        permissions: &ImagePermissions,
    ) -> Self {
        Self {
            inner: InnerImageSegment::bytes(name, virtual_address, data, permissions.inner),
        }
    }

    #[staticmethod]
    #[pyo3(text_signature = "(name, virtual_address, size, permissions)")]
    pub fn zeroes(
        name: Option<String>,
        virtual_address: u64,
        size: u64,
        permissions: &ImagePermissions,
    ) -> Self {
        Self {
            inner: InnerImageSegment::zeroes(name, virtual_address, size, permissions.inner),
        }
    }

    #[getter]
    pub fn name(&self) -> Option<String> {
        self.inner.name.clone()
    }

    #[getter]
    pub fn virtual_address(&self) -> u64 {
        self.inner.virtual_address
    }

    #[getter]
    pub fn size(&self) -> u64 {
        self.inner.size
    }

    #[getter]
    pub fn permissions(&self) -> ImagePermissions {
        ImagePermissions {
            inner: self.inner.permissions,
        }
    }

    #[pyo3(text_signature = "($self)")]
    pub fn end(&self) -> u64 {
        self.inner.end()
    }

    #[pyo3(text_signature = "($self, address)")]
    pub fn contains(&self, address: u64) -> bool {
        self.inner.contains(address)
    }
}

/// Virtual binary image backed by mapped segments.
#[pyclass]
pub struct Image {
    pub inner: InnerImage,
}

impl Image {
    pub fn from_inner(inner: InnerImage) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl Image {
    #[new]
    #[pyo3(text_signature = "()")]
    pub fn new() -> Self {
        Self {
            inner: InnerImage::new(),
        }
    }

    #[pyo3(text_signature = "($self, segment)")]
    pub fn add_segment(&mut self, segment: &ImageSegment) {
        self.inner.add_segment(segment.inner.clone());
    }

    #[pyo3(text_signature = "($self)")]
    pub fn segments(&self) -> Vec<ImageSegment> {
        self.inner
            .segments()
            .iter()
            .cloned()
            .map(|inner| ImageSegment { inner })
            .collect()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn snapshot(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        json_value_to_py(
            py,
            &serde_json::to_value(&self.inner)
                .map_err(|error| PyRuntimeError::new_err(error.to_string()))?,
        )
    }

    #[staticmethod]
    #[pyo3(text_signature = "(snapshot)")]
    pub fn from_snapshot(py: Python<'_>, snapshot: Py<PyAny>) -> PyResult<Self> {
        let inner = serde_json::from_value(py_to_json_value(py, snapshot)?)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(Self { inner })
    }

    #[pyo3(text_signature = "($self, address, size)")]
    pub fn read_virtual_address(
        &self,
        py: Python<'_>,
        address: u64,
        size: usize,
    ) -> PyResult<Option<Py<PyBytes>>> {
        self.inner
            .read_virtual_address(address, size)
            .map(|value| value.map(|bytes| PyBytes::new(py, &bytes).unbind()))
            .map_err(|error| PyValueError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self, address)")]
    pub fn is_virtual_address(&self, address: u64) -> bool {
        self.inner.is_virtual_address(address)
    }

    #[pyo3(text_signature = "($self)")]
    pub fn mapped_size(&self) -> u64 {
        self.inner.mapped_size()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn executable_virtual_address_ranges(&self) -> BTreeMap<u64, u64> {
        self.inner.executable_virtual_address_ranges()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn virtual_min(&self) -> Option<u64> {
        self.inner.virtual_min()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn virtual_max(&self) -> Option<u64> {
        self.inner.virtual_max()
    }

    pub fn __contains__(&self, address: u64) -> bool {
        self.is_virtual_address(address)
    }

    pub fn __getitem__(&self, py: Python<'_>, key: Py<PyAny>) -> PyResult<Py<PyAny>> {
        let key = key.bind(py);
        if key.hasattr("start")? && key.hasattr("stop")? {
            return self.get_slice(py, key);
        }

        let address = key.extract::<u64>()?;
        let Some(bytes) = self
            .inner
            .read_virtual_address(address, 1)
            .map_err(|error| PyValueError::new_err(error.to_string()))?
        else {
            return Err(PyIndexError::new_err("virtual address is unmapped"));
        };
        let Some(byte) = bytes.first() else {
            return Err(PyIndexError::new_err("virtual address is unmapped"));
        };
        Ok((*byte).into_pyobject(py)?.unbind().into_any())
    }

    fn get_slice(&self, py: Python<'_>, key: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
        let step = key.getattr("step")?;
        if !step.is_none() && step.extract::<i64>()? != 1 {
            return Err(PyValueError::new_err(
                "image slices do not support step values",
            ));
        }

        let start = key.getattr("start")?;
        let start = if start.is_none() {
            self.inner.virtual_min().unwrap_or(0)
        } else {
            start.extract::<u64>()?
        };

        let stop = key.getattr("stop")?;
        let stop = if stop.is_none() {
            self.inner.virtual_max().unwrap_or(start)
        } else {
            stop.extract::<u64>()?
        };

        if stop < start {
            return Err(PyValueError::new_err("image slice stop is before start"));
        }

        let size = usize::try_from(stop - start)
            .map_err(|_| PyValueError::new_err("image slice is too large"))?;
        let bytes = self
            .inner
            .read_virtual_address(start, size)
            .map_err(|error| PyValueError::new_err(error.to_string()))?
            .unwrap_or_default();
        Ok(PyBytes::new(py, &bytes).unbind().into_any())
    }
}

#[pymodule]
#[pyo3(name = "image")]
pub fn image_init(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<ImagePermissions>()?;
    m.add_class::<ImageSegment>()?;
    m.add_class::<Image>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.formats.image", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.formats.image")?;
    Ok(())
}
