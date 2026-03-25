use pyo3::prelude::*;

#[pyfunction]
#[pyo3(text_signature = "(lhs, rhs)")]
pub fn dot(lhs: Vec<f32>, rhs: Vec<f32>) -> f32 {
    binlex::math::similarity::dot(&lhs, &rhs)
}

#[pyfunction]
#[pyo3(text_signature = "(lhs, rhs)")]
pub fn cosine(lhs: Vec<f32>, rhs: Vec<f32>) -> f32 {
    binlex::math::similarity::cosine(&lhs, &rhs)
}

#[pyfunction]
#[pyo3(text_signature = "(lhs, rhs)")]
pub fn euclidean(lhs: Vec<f32>, rhs: Vec<f32>) -> f32 {
    binlex::math::similarity::euclidean(&lhs, &rhs)
}

#[pyfunction]
#[pyo3(text_signature = "(lhs, rhs)")]
pub fn manhattan(lhs: Vec<f32>, rhs: Vec<f32>) -> f32 {
    binlex::math::similarity::manhattan(&lhs, &rhs)
}

#[pyfunction]
#[pyo3(text_signature = "(lhs, rhs)")]
pub fn chebyshev(lhs: Vec<f32>, rhs: Vec<f32>) -> f32 {
    binlex::math::similarity::chebyshev(&lhs, &rhs)
}

#[pyfunction]
#[pyo3(text_signature = "(lhs, rhs)")]
pub fn hamming(lhs: Vec<u32>, rhs: Vec<u32>) -> usize {
    binlex::math::similarity::hamming(&lhs, &rhs)
}

#[pyfunction]
#[pyo3(text_signature = "(lhs, rhs)")]
pub fn jaccard_signature(lhs: Vec<u32>, rhs: Vec<u32>) -> f64 {
    binlex::math::similarity::jaccard_signature(&lhs, &rhs)
}

#[pyfunction]
#[pyo3(text_signature = "(lhs, rhs)")]
pub fn jaccard_set(lhs: Vec<u32>, rhs: Vec<u32>) -> f64 {
    binlex::math::similarity::jaccard_set(&lhs, &rhs)
}

#[pyfunction]
#[pyo3(text_signature = "(lhs, rhs)")]
pub fn dice(lhs: Vec<u32>, rhs: Vec<u32>) -> f64 {
    binlex::math::similarity::dice(&lhs, &rhs)
}

#[pyfunction]
#[pyo3(text_signature = "(lhs, rhs)")]
pub fn overlap_coefficient(lhs: Vec<u32>, rhs: Vec<u32>) -> f64 {
    binlex::math::similarity::overlap_coefficient(&lhs, &rhs)
}

#[pyfunction]
#[pyo3(text_signature = "(lhs, rhs)")]
pub fn pearson(lhs: Vec<f32>, rhs: Vec<f32>) -> f64 {
    binlex::math::similarity::pearson(&lhs, &rhs)
}

pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = PyModule::new(py, "similarity")?;
    m.add_function(wrap_pyfunction!(dot, &m)?)?;
    m.add_function(wrap_pyfunction!(cosine, &m)?)?;
    m.add_function(wrap_pyfunction!(euclidean, &m)?)?;
    m.add_function(wrap_pyfunction!(manhattan, &m)?)?;
    m.add_function(wrap_pyfunction!(chebyshev, &m)?)?;
    m.add_function(wrap_pyfunction!(hamming, &m)?)?;
    m.add_function(wrap_pyfunction!(jaccard_signature, &m)?)?;
    m.add_function(wrap_pyfunction!(jaccard_set, &m)?)?;
    m.add_function(wrap_pyfunction!(dice, &m)?)?;
    m.add_function(wrap_pyfunction!(overlap_coefficient, &m)?)?;
    m.add_function(wrap_pyfunction!(pearson, &m)?)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.math.similarity", &m)?;
    m.setattr("__name__", "binlex_bindings.binlex.math.similarity")?;
    parent.add_submodule(&m)?;
    Ok(())
}
