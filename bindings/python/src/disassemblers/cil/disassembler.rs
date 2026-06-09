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
use crate::controlflow::{Block, Function, Instruction};
use crate::formats::Image;
use crate::Architecture;
use crate::Configuration;
use binlex::disassemblers::cil::Disassembler as InnerDisassembler;
use binlex::Architecture as InnerArchitecture;
use binlex::Configuration as InnerConfiguration;
use memmap2::Mmap;
use pyo3::buffer::PyBuffer;
use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;
use pyo3::types::PyAny;
use pyo3::types::PyBytes;
use pyo3::types::PyMemoryView;
use pyo3::Py;
use serde_json::Value;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::io::Error;

fn parse_metadata_address(value: &str) -> Option<u64> {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16).ok();
    }
    value.parse::<u64>().ok()
}

fn metadata_token_addresses(graph: &binlex::controlflow::Graph) -> BTreeMap<u64, u64> {
    let metadata = graph.metadata();
    let Some(Value::Object(cil)) = metadata.get("cil") else {
        return BTreeMap::new();
    };
    let Some(Value::Object(tokens)) = cil.get("metadata_token_virtual_addresses") else {
        return BTreeMap::new();
    };
    tokens
        .iter()
        .filter_map(|(token, address)| Some((parse_metadata_address(token)?, address.as_u64()?)))
        .collect()
}

#[pyclass(unsendable)]
pub struct Disassembler {
    image: Option<Py<Image>>,
    bytes: Option<Py<PyBytes>>,
    memory_view: Option<Py<PyMemoryView>>,
    machine: Py<Architecture>,
    executable_address_ranges: BTreeMap<u64, u64>,
    config: Py<Configuration>,
}

enum MaterializedInput {
    Bytes(Vec<u8>),
    MappedImage { mmap: Mmap, base: u64 },
}

impl Disassembler {
    fn materialize_input(
        &self,
        py: Python<'_>,
    ) -> PyResult<(
        InnerArchitecture,
        MaterializedInput,
        BTreeMap<u64, u64>,
        InnerConfiguration,
    )> {
        let machine = self.machine.borrow(py).inner;
        let config = self.config.borrow(py).inner.lock().unwrap().clone();

        if let Some(bytes) = &self.bytes {
            let bytes = bytes.bind(py);
            return Ok((
                machine,
                MaterializedInput::Bytes(bytes.as_bytes().to_vec()),
                self.executable_address_ranges.clone(),
                config,
            ));
        }

        if let Some(memory_view) = &self.memory_view {
            let memory_view = memory_view.bind(py);
            let buffer = PyBuffer::<u8>::get(memory_view.as_any())?;

            if !buffer.is_c_contiguous() {
                return Err(PyTypeError::new_err("the memoryview is not c-contiguous"));
            }

            let slice = buffer
                .as_slice(py)
                .ok_or_else(|| PyTypeError::new_err("failed to read bytes from memoryview"))?;
            let image =
                unsafe { std::slice::from_raw_parts(slice.as_ptr() as *const u8, slice.len()) };
            return Ok((
                machine,
                MaterializedInput::Bytes(image.to_vec()),
                self.executable_address_ranges.clone(),
                config,
            ));
        }

        if let Some(image) = &self.image {
            let mut image = image.borrow_mut(py);
            let image_base = image.inner.base();
            let _ = image
                .inner
                .mmap()
                .map_err(|error| PyTypeError::new_err(error.to_string()))?;
            let handle = image
                .inner
                .handle
                .as_ref()
                .ok_or_else(|| PyTypeError::new_err("image file handle is closed"))?;
            let mmap = unsafe { Mmap::map(handle) }
                .map_err(|error| PyTypeError::new_err(error.to_string()))?;
            return Ok((
                machine,
                MaterializedInput::MappedImage {
                    mmap,
                    base: image_base,
                },
                self.executable_address_ranges.clone(),
                config,
            ));
        }

        Err(PyTypeError::new_err(
            "expected an Image, bytes, or memoryview object for the 'image' argument",
        ))
    }
}

#[pymethods]
impl Disassembler {
    #[new]
    #[pyo3(text_signature = "(machine, image, executable_address_ranges, configuration)")]
    pub fn new(
        py: Python,
        machine: Py<Architecture>,
        image: Py<PyAny>,
        executable_address_ranges: BTreeMap<u64, u64>,
        configuration: Py<Configuration>,
    ) -> PyResult<Self> {
        if let Ok(image) = image.extract::<Py<Image>>(py) {
            return Ok(Self {
                image: Some(image),
                bytes: None,
                memory_view: None,
                machine,
                executable_address_ranges,
                config: configuration,
            });
        }

        if let Ok(bytes) = image.extract::<Py<PyBytes>>(py) {
            return Ok(Self {
                image: None,
                bytes: Some(bytes),
                memory_view: None,
                machine,
                executable_address_ranges,
                config: configuration,
            });
        }

        if let Ok(memory_view) = image.extract::<Py<PyMemoryView>>(py) {
            return Ok(Self {
                image: None,
                bytes: None,
                memory_view: Some(memory_view),
                machine,
                executable_address_ranges,
                config: configuration,
            });
        }

        Err(PyTypeError::new_err(
            "expected an Image, bytes, or memoryview object for the 'image' argument",
        ))
    }

    #[pyo3(text_signature = "($self, address, graph)")]
    pub fn disassemble_instruction(
        &self,
        py: Python,
        address: u64,
        graph: Py<Graph>,
    ) -> Result<Instruction, Error> {
        let (machine, input, executable_address_ranges, config) = self
            .materialize_input(py)
            .map_err(|error| Error::other(error.to_string()))?;
        let graph_inner = graph.borrow(py).inner.clone();
        let metadata_token_addresses = metadata_token_addresses(&graph_inner.lock().unwrap());
        let result = py
            .detach(move || match input {
                MaterializedInput::Bytes(image) => {
                    let disassembler =
                        InnerDisassembler::new(machine, &image, executable_address_ranges, config)?;
                    disassembler.disassemble_instruction_address(
                        address,
                        &metadata_token_addresses,
                        &mut graph_inner.lock().unwrap(),
                    )
                }
                MaterializedInput::MappedImage { mmap, base } => {
                    let disassembler = InnerDisassembler::new_with_image_base(
                        machine,
                        &mmap[..],
                        base,
                        executable_address_ranges,
                        config,
                    )?;
                    disassembler.disassemble_instruction_address(
                        address,
                        &metadata_token_addresses,
                        &mut graph_inner.lock().unwrap(),
                    )
                }
            })
            .map_err(|error| Error::other(error.to_string()))?;
        Instruction::new(result, graph.clone_ref(py))
            .map_err(|error| Error::other(error.to_string()))
    }

    #[pyo3(text_signature = "($self, address, graph)")]
    pub fn disassemble_function(
        &self,
        py: Python,
        address: u64,
        graph: Py<Graph>,
    ) -> Result<Function, Error> {
        let (machine, input, executable_address_ranges, config) = self
            .materialize_input(py)
            .map_err(|error| Error::other(error.to_string()))?;
        let graph_inner = graph.borrow(py).inner.clone();
        let metadata_token_addresses = metadata_token_addresses(&graph_inner.lock().unwrap());
        let result = py
            .detach(move || match input {
                MaterializedInput::Bytes(image) => {
                    let disassembler =
                        InnerDisassembler::new(machine, &image, executable_address_ranges, config)?;
                    disassembler.disassemble_function_address(
                        address,
                        &metadata_token_addresses,
                        &mut graph_inner.lock().unwrap(),
                    )
                }
                MaterializedInput::MappedImage { mmap, base } => {
                    let disassembler = InnerDisassembler::new_with_image_base(
                        machine,
                        &mmap[..],
                        base,
                        executable_address_ranges,
                        config,
                    )?;
                    disassembler.disassemble_function_address(
                        address,
                        &metadata_token_addresses,
                        &mut graph_inner.lock().unwrap(),
                    )
                }
            })
            .map_err(|error| Error::other(error.to_string()))?;
        Function::new(result, graph.clone_ref(py)).map_err(|error| Error::other(error.to_string()))
    }

    #[pyo3(text_signature = "($self, address, graph)")]
    pub fn disassemble_block(
        &self,
        py: Python,
        address: u64,
        graph: Py<Graph>,
    ) -> Result<Block, Error> {
        let (machine, input, executable_address_ranges, config) = self
            .materialize_input(py)
            .map_err(|error| Error::other(error.to_string()))?;
        let graph_inner = graph.borrow(py).inner.clone();
        let metadata_token_addresses = metadata_token_addresses(&graph_inner.lock().unwrap());
        py.detach(move || match input {
            MaterializedInput::Bytes(image) => {
                let disassembler =
                    InnerDisassembler::new(machine, &image, executable_address_ranges, config)?;
                disassembler.disassemble_block_address(
                    address,
                    &metadata_token_addresses,
                    &mut graph_inner.lock().unwrap(),
                )
            }
            MaterializedInput::MappedImage { mmap, base } => {
                let disassembler = InnerDisassembler::new_with_image_base(
                    machine,
                    &mmap[..],
                    base,
                    executable_address_ranges,
                    config,
                )?;
                disassembler.disassemble_block_address(
                    address,
                    &metadata_token_addresses,
                    &mut graph_inner.lock().unwrap(),
                )
            }
        })
        .map_err(|error| Error::other(error.to_string()))?;
        Block::new(address, graph.clone_ref(py)).map_err(|error| Error::other(error.to_string()))
    }

    #[pyo3(text_signature = "($self, addresses, graph)")]
    pub fn disassemble(
        &self,
        py: Python,
        addresses: BTreeSet<u64>,
        graph: Py<Graph>,
    ) -> Result<(), Error> {
        let (machine, input, executable_address_ranges, config) = self
            .materialize_input(py)
            .map_err(|error| Error::other(error.to_string()))?;
        let graph_inner = graph.borrow(py).inner.clone();
        let metadata_token_addresses = metadata_token_addresses(&graph_inner.lock().unwrap());
        py.detach(move || match input {
            MaterializedInput::Bytes(image) => {
                let disassembler =
                    InnerDisassembler::new(machine, &image, executable_address_ranges, config)?;
                disassembler.disassemble(
                    addresses,
                    metadata_token_addresses,
                    &mut graph_inner.lock().unwrap(),
                )
            }
            MaterializedInput::MappedImage { mmap, base } => {
                let disassembler = InnerDisassembler::new_with_image_base(
                    machine,
                    &mmap[..],
                    base,
                    executable_address_ranges,
                    config,
                )?;
                disassembler.disassemble(
                    addresses,
                    metadata_token_addresses,
                    &mut graph_inner.lock().unwrap(),
                )
            }
        })
        .map_err(|error| Error::other(error.to_string()))?;
        Ok(())
    }
}

#[pymodule]
#[pyo3(name = "binlex_cil_disassembler")]
pub fn binlex_cil_disassembler_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Disassembler>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.disassemblers.cil", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.disassemblers.cil")?;
    Ok(())
}
