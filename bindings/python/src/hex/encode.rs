use pyo3::prelude::*;

#[pyfunction]
#[pyo3(text_signature = "(bytes)")]
pub fn encode(bytes: Vec<u8>) -> String {
    binlex::hex::encode(&bytes)
}
