use pyo3::prelude::*;

use binlex::hashing::minhash::MinHash32 as InnerMinHash32;

#[pyclass]
pub struct MinHash32 {
    num_hashes: usize,
    shingle_size: usize,
    seed: u64,
    bytes: Vec<u8>,
}

#[pymethods]
impl MinHash32 {
    #[new]
    #[pyo3(text_signature = "(bytes, num_hashes, shingle_size, seed)")]
    pub fn new(bytes: Vec<u8>, num_hashes: usize, shingle_size: usize, seed: u64) -> Self {
        Self {
            bytes: bytes,
            num_hashes: num_hashes,
            shingle_size: shingle_size,
            seed: seed,
        }
    }
    #[pyo3(text_signature = "($self)")]
    pub fn hexdigest(&self) -> Option<String> {
        InnerMinHash32::new(&self.bytes, self.num_hashes, self.shingle_size, self.seed).hexdigest()
    }
}


#[pymodule]
#[pyo3(name = "minhash")]
pub fn minhash_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<MinHash32>()?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("binlex.hashing.minhash", m)?;
    m.setattr("__name__", "binlex.hashing.minhash")?;
    Ok(())
}
