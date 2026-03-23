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

use crate::controlflow::Graph;
use crate::formats::Image;
use crate::Architecture;
use crate::Config;
use binlex::disassemblers::capstone::Disassembler as InnerDisassembler;
use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::Py;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::io::Error;

#[pyclass(unsendable)]
pub struct Disassembler {
    image: Option<Py<Image>>,
    bytes: Option<Py<PyBytes>>,
    machine: Py<Architecture>,
    executable_address_ranges: BTreeMap<u64, u64>,
    config: Py<Config>,
}

impl Disassembler {
    fn with_inner_disassembler<T, F>(&self, py: Python, f: F) -> PyResult<T>
    where
        F: FnOnce(InnerDisassembler<'_>) -> Result<T, Error>,
    {
        let machine = self.machine.borrow(py).inner;
        let config = self.config.borrow(py).inner.lock().unwrap().clone();
        if let Some(bytes) = &self.bytes {
            let bytes = bytes.bind(py);
            let disassembler = InnerDisassembler::new(
                machine,
                bytes.as_bytes(),
                self.executable_address_ranges.clone(),
                config,
            )
            .map_err(|error| PyTypeError::new_err(error.to_string()))?;
            return f(disassembler).map_err(PyErr::from);
        }
        if let Some(image) = &self.image {
            let mut image = image.borrow_mut(py);
            let mmap = image
                .inner
                .mmap()
                .map_err(|error| PyTypeError::new_err(error.to_string()))?;
            let disassembler = InnerDisassembler::new(
                machine,
                &mmap[..],
                self.executable_address_ranges.clone(),
                config,
            )
            .map_err(|error| PyTypeError::new_err(error.to_string()))?;
            return f(disassembler).map_err(PyErr::from);
        }
        Err(PyTypeError::new_err(
            "expected an Image or bytes object for the 'image' argument",
        ))
    }
}

#[pymethods]
impl Disassembler {
    #[new]
    #[pyo3(text_signature = "(machine, image, executable_address_ranges, config)")]
    pub fn new(
        py: Python,
        machine: Py<Architecture>,
        image: Py<PyAny>,
        executable_address_ranges: BTreeMap<u64, u64>,
        config: Py<Config>,
    ) -> PyResult<Self> {
        if let Ok(image) = image.extract::<Py<Image>>(py) {
            return Ok(Self {
                image: Some(image),
                bytes: None,
                machine,
                executable_address_ranges,
                config,
            });
        }
        if let Ok(bytes) = image.extract::<Py<PyBytes>>(py) {
            return Ok(Self {
                image: None,
                bytes: Some(bytes),
                machine,
                executable_address_ranges,
                config,
            });
        }
        Err(PyTypeError::new_err(
            "expected an Image or bytes object for the 'image' argument",
        ))
    }

    #[pyo3(text_signature = "($self, address, cfg)")]
    pub fn disassemble_instruction(
        &self,
        py: Python,
        address: u64,
        cfg: Py<Graph>,
    ) -> Result<u64, Error> {
        let cfg_ref = &mut cfg.borrow_mut(py);
        let result = self
            .with_inner_disassembler(py, |disassembler| {
                disassembler.disassemble_instruction(address, &mut cfg_ref.inner.lock().unwrap())
            })
            .map_err(|error| Error::other(error.to_string()))?;
        Ok(result)
    }

    #[pyo3(text_signature = "($self, address, cfg)")]
    pub fn disassemble_function(
        &self,
        py: Python,
        address: u64,
        cfg: Py<Graph>,
    ) -> Result<u64, Error> {
        let cfg_ref = &mut cfg.borrow_mut(py);
        let result = self
            .with_inner_disassembler(py, |disassembler| {
                disassembler.disassemble_function(address, &mut cfg_ref.inner.lock().unwrap())
            })
            .map_err(|error| Error::other(error.to_string()))?;
        Ok(result)
    }

    #[pyo3(text_signature = "($self, address, cfg)")]
    pub fn disassemble_block(
        &self,
        py: Python,
        address: u64,
        cfg: Py<Graph>,
    ) -> Result<u64, Error> {
        let cfg_ref = &mut cfg.borrow_mut(py);
        let result = self
            .with_inner_disassembler(py, |disassembler| {
                disassembler.disassemble_block(address, &mut cfg_ref.inner.lock().unwrap())
            })
            .map_err(|error| Error::other(error.to_string()))?;
        Ok(result)
    }

    #[pyo3(text_signature = "($self, addresses, cfg)")]
    pub fn disassemble_controlflow(
        &self,
        py: Python,
        addresses: BTreeSet<u64>,
        cfg: Py<Graph>,
    ) -> Result<(), Error> {
        let cfg_ref = &mut cfg.borrow_mut(py);
        self.with_inner_disassembler(py, |disassembler| {
            disassembler.disassemble_controlflow(addresses, &mut cfg_ref.inner.lock().unwrap())
        })
        .map_err(|error| Error::other(error.to_string()))?;
        Ok(())
    }

    #[pyo3(text_signature = "($self)")]
    pub fn disassemble_sweep(&self, py: Python) -> Result<BTreeSet<u64>, Error> {
        let results = self
            .with_inner_disassembler(py, |disassembler| Ok(disassembler.disassemble_sweep()))
            .map_err(|error| Error::other(error.to_string()))?;
        let mut asdf = BTreeSet::<u64>::new();
        for result in results {
            asdf.insert(result);
        }
        Ok(asdf)
    }
}

#[pymodule]
#[pyo3(name = "disassembler")]
pub fn disassembler_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Disassembler>()?;
    py.import("sys")?.getattr("modules")?.set_item(
        "binlex_bindings.binlex.disassemblers.capstone.disassembler",
        m,
    )?;
    m.setattr(
        "__name__",
        "binlex_bindings.binlex.disassemblers.capstone.disassembler",
    )?;
    Ok(())
}
