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
use crate::Architecture;
use crate::Config;
use binlex::disassemblers::custom::cil::Disassembler as InnerDisassembler;
use pyo3::buffer::PyBuffer;
use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;
use pyo3::types::PyAny;
use pyo3::types::PyBytes;
use pyo3::types::PyMemoryView;
use pyo3::Py;
use std::borrow::Borrow;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::io::Error;

#[pyclass(unsendable)]
pub struct Disassembler {
    image: Py<PyAny>,
    machine: Py<Architecture>,
    metadata_token_addresses: BTreeMap<u64, u64>,
    executable_address_ranges: BTreeMap<u64, u64>,
    config: Py<Config>,
}

#[pymethods]
impl Disassembler {
    #[new]
    #[pyo3(text_signature = "(machine, image, executable_address_ranges, config)")]
    pub fn new(
        machine: Py<Architecture>,
        image: Py<PyAny>,
        metadata_token_addresses: BTreeMap<u64, u64>,
        executable_address_ranges: BTreeMap<u64, u64>,
        config: Py<Config>,
    ) -> Self {
        Self {
            machine,
            image,
            metadata_token_addresses,
            executable_address_ranges,
            config,
        }
    }

    fn get_image_data<'py>(&'py self, py: Python<'py>) -> PyResult<&'py [u8]> {
        let image_ref = self.image.borrow();

        if let Ok(bytes) = image_ref.downcast_bound::<PyBytes>(py) {
            return Ok(bytes.as_bytes());
        }

        if let Ok(memory_view) = image_ref.downcast_bound::<PyMemoryView>(py) {
            let buffer = PyBuffer::<u8>::get_bound(memory_view)?;

            if !buffer.is_c_contiguous() {
                return Err(PyTypeError::new_err("the memoryview is not c-contiguous"));
            }

            let slice = buffer.as_slice(py).unwrap();

            let result: &[u8] =
                unsafe { std::slice::from_raw_parts(slice.as_ptr() as *const u8, slice.len()) };

            return Ok(result);
        }

        Err(PyTypeError::new_err(
            "expected a bytes or memoryview object for the 'image' argument",
        ))
    }

    #[pyo3(text_signature = "($self, address, cfg)")]
    pub fn disassemble_instruction(
        &self,
        py: Python,
        address: u64,
        cfg: Py<Graph>,
    ) -> Result<u64, Error> {
        let image = self.get_image_data(py)?;
        let machine_binding = &self.machine.borrow(py);
        let inner_config = self.config.borrow(py).inner.lock().unwrap().clone();
        let disassembler = InnerDisassembler::new(
            machine_binding.inner,
            image,
            self.metadata_token_addresses.clone(),
            self.executable_address_ranges.clone(),
            inner_config,
        )?;
        let cfg_ref = &mut cfg.borrow_mut(py);
        let result =
            disassembler.disassemble_instruction(address, &mut cfg_ref.inner.lock().unwrap())?;
        Ok(result)
    }

    #[pyo3(text_signature = "($self, address, cfg)")]
    pub fn disassemble_function(
        &self,
        py: Python,
        address: u64,
        cfg: Py<Graph>,
    ) -> Result<u64, Error> {
        let image = self.get_image_data(py)?;
        let machine_binding = &self.machine.borrow(py);
        let inner_config = self.config.borrow(py).inner.lock().unwrap().clone();
        let disassembler = InnerDisassembler::new(
            machine_binding.inner,
            image,
            self.metadata_token_addresses.clone(),
            self.executable_address_ranges.clone(),
            inner_config,
        )?;
        let cfg_ref = &mut cfg.borrow_mut(py);
        let result =
            disassembler.disassemble_function(address, &mut cfg_ref.inner.lock().unwrap())?;
        Ok(result)
    }

    #[pyo3(text_signature = "($self, address, cfg)")]
    pub fn disassemble_block(
        &self,
        py: Python,
        address: u64,
        cfg: Py<Graph>,
    ) -> Result<u64, Error> {
        let image = self.get_image_data(py)?;
        let machine_binding = &self.machine.borrow(py);
        let inner_config = self.config.borrow(py).inner.lock().unwrap().clone();
        let disassembler = InnerDisassembler::new(
            machine_binding.inner,
            image,
            self.metadata_token_addresses.clone(),
            self.executable_address_ranges.clone(),
            inner_config,
        )?;
        let cfg_ref = &mut cfg.borrow_mut(py);
        let result = disassembler.disassemble_block(address, &mut cfg_ref.inner.lock().unwrap())?;
        Ok(result)
    }

    #[pyo3(text_signature = "($self, addresses, cfg)")]
    pub fn disassemble_controlflow(
        &self,
        py: Python,
        addresses: BTreeSet<u64>,
        cfg: Py<Graph>,
    ) -> Result<(), Error> {
        let image = self.get_image_data(py)?;
        let machine_binding = &self.machine.borrow(py);
        let inner_config = self.config.borrow(py).inner.lock().unwrap().clone();
        let disassembler = InnerDisassembler::new(
            machine_binding.inner,
            image,
            self.metadata_token_addresses.clone(),
            self.executable_address_ranges.clone(),
            inner_config,
        )?;
        let cfg_ref = &mut cfg.borrow_mut(py);
        disassembler.disassemble_controlflow(addresses, &mut cfg_ref.inner.lock().unwrap())?;
        Ok(())
    }
}

#[pymodule]
#[pyo3(name = "binlex_cil_disassembler")]
pub fn binlex_cil_disassembler_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Disassembler>()?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.disassemblers.custom.cil", m)?;
    m.setattr(
        "__name__",
        "binlex_bindings.binlex.disassemblers.custom.cil",
    )?;
    Ok(())
}
