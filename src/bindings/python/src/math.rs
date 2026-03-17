use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

#[pyfunction]
#[pyo3(text_signature = "(values)")]
pub fn normalize_l2(values: Vec<f32>) -> Vec<f32> {
    let mut values = values;
    binlex::math::stats::normalize_l2(&mut values);
    values
}

#[pyfunction]
#[pyo3(text_signature = "(values)")]
pub fn mean(values: Vec<f32>) -> f32 {
    binlex::math::stats::mean(&values)
}

#[pyfunction]
#[pyo3(text_signature = "(values)")]
pub fn max_or_zero(values: Vec<f32>) -> f32 {
    binlex::math::stats::max_or_zero(&values)
}

#[pyfunction]
#[pyo3(text_signature = "(values, weights)")]
pub fn weighted_mean(values: Vec<f32>, weights: Vec<f32>) -> PyResult<f32> {
    if values.len() != weights.len() {
        return Err(PyValueError::new_err(
            "values and weights must have the same length",
        ));
    }
    Ok(binlex::math::stats::weighted_mean(&values, &weights))
}

#[pyfunction]
#[pyo3(text_signature = "(values, weights, buckets, scale)")]
pub fn weighted_histogram(
    values: Vec<f32>,
    weights: Vec<f32>,
    buckets: usize,
    scale: f32,
) -> PyResult<Vec<f32>> {
    if values.len() != weights.len() {
        return Err(PyValueError::new_err(
            "values and weights must have the same length",
        ));
    }
    Ok(binlex::math::stats::weighted_histogram(
        &values, &weights, buckets, scale,
    ))
}

#[pyfunction]
#[pyo3(text_signature = "(values, dimensions)")]
pub fn downsample_vector(values: Vec<f32>, dimensions: usize) -> Vec<f32> {
    binlex::math::stats::downsample_vector(&values, dimensions)
}

#[pymodule]
#[pyo3(name = "math")]
pub fn math_init(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(normalize_l2, m)?)?;
    m.add_function(wrap_pyfunction!(mean, m)?)?;
    m.add_function(wrap_pyfunction!(max_or_zero, m)?)?;
    m.add_function(wrap_pyfunction!(weighted_mean, m)?)?;
    m.add_function(wrap_pyfunction!(weighted_histogram, m)?)?;
    m.add_function(wrap_pyfunction!(downsample_vector, m)?)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.math", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.math")?;
    Ok(())
}
