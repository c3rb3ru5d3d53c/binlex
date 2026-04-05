use pyo3::exceptions::{PyIOError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyAny;
use pyo3::types::PyBool;

use ::binlex::yara::{
    CompiledRuleSet as InnerCompiledRuleSet, MetaValue as InnerMetaValue, Pattern as InnerPattern,
    PatternKind as InnerPatternKind, Rule as InnerRule, RuleMatch as InnerRuleMatch,
    RuleSet as InnerRuleSet, ScanResults as InnerScanResults,
};

#[pyclass(name = "Pattern", skip_from_py_object)]
#[derive(Clone)]
pub struct Pattern {
    inner: InnerPattern,
}

#[pymethods]
impl Pattern {
    pub fn name(&self) -> String {
        self.inner.name.clone()
    }

    pub fn pattern(&self) -> String {
        self.inner.value.clone()
    }

    pub fn comment(&self) -> Option<String> {
        self.inner.comment.clone()
    }

    pub fn kind(&self) -> String {
        match self.inner.kind {
            InnerPatternKind::Hex => "hex".to_string(),
            InnerPatternKind::Text => "text".to_string(),
            InnerPatternKind::Regex => "regex".to_string(),
            InnerPatternKind::String => "string".to_string(),
        }
    }

    pub fn ascii(&self) -> bool {
        self.inner.ascii
    }

    pub fn wide(&self) -> bool {
        self.inner.wide
    }
}

#[pyclass(name = "Rule")]
pub struct Rule {
    inner: std::sync::Mutex<InnerRule>,
}

#[pyclass(name = "RuleMatch", skip_from_py_object)]
#[derive(Clone)]
pub struct RuleMatch {
    inner: InnerRuleMatch,
}

#[pymethods]
impl RuleMatch {
    pub fn rule(&self) -> String {
        self.inner.rule().to_string()
    }

    pub fn offset(&self) -> usize {
        self.inner.offset()
    }

    pub fn data(&self) -> Vec<u8> {
        self.inner.data().to_vec()
    }

    pub fn size(&self) -> usize {
        self.inner.size()
    }
}

#[pyclass(name = "ScanResults")]
pub struct ScanResults {
    inner: InnerScanResults,
}

#[pymethods]
impl ScanResults {
    pub fn matches(&self) -> Vec<RuleMatch> {
        self.inner
            .matches()
            .iter()
            .cloned()
            .map(|inner| RuleMatch { inner })
            .collect()
    }
}

#[pyclass(name = "CompiledRuleSet")]
pub struct CompiledRuleSet {
    inner: std::sync::Mutex<InnerCompiledRuleSet>,
}

#[pymethods]
impl CompiledRuleSet {
    pub fn scan(&self, data: Vec<u8>) -> PyResult<ScanResults> {
        let results = self
            .inner
            .lock()
            .unwrap()
            .scan(&data)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(ScanResults { inner: results })
    }

    pub fn scan_file(&self, path: String) -> PyResult<ScanResults> {
        let results = self
            .inner
            .lock()
            .unwrap()
            .scan_file(path)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(ScanResults { inner: results })
    }
}

#[pyclass(name = "RuleSet")]
pub struct RuleSet {
    inner: std::sync::Mutex<InnerRuleSet>,
}

#[pymethods]
impl RuleSet {
    #[new]
    pub fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(InnerRuleSet::new()),
        }
    }

    pub fn add(&self, rule: &Rule) {
        self.inner
            .lock()
            .unwrap()
            .add(rule.inner.lock().unwrap().clone());
    }

    pub fn remove(&self, name: String) -> bool {
        self.inner.lock().unwrap().remove(&name)
    }

    pub fn clear(&self) {
        self.inner.lock().unwrap().clear();
    }

    pub fn rules(&self) -> Vec<Rule> {
        self.inner
            .lock()
            .unwrap()
            .rules()
            .iter()
            .cloned()
            .map(|inner| Rule {
                inner: std::sync::Mutex::new(inner),
            })
            .collect()
    }

    pub fn check(&self) -> bool {
        self.inner.lock().unwrap().check()
    }

    pub fn compile(&self) -> PyResult<CompiledRuleSet> {
        let compiled = self
            .inner
            .lock()
            .unwrap()
            .compile()
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(CompiledRuleSet {
            inner: std::sync::Mutex::new(compiled),
        })
    }

    pub fn scan(&self, data: Vec<u8>) -> PyResult<ScanResults> {
        let results = self
            .inner
            .lock()
            .unwrap()
            .scan(&data)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(ScanResults { inner: results })
    }

    pub fn scan_file(&self, path: String) -> PyResult<ScanResults> {
        let results = self
            .inner
            .lock()
            .unwrap()
            .scan_file(path)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(ScanResults { inner: results })
    }
}

#[pymethods]
impl Rule {
    #[new]
    #[pyo3(signature = (name=None, comment=None))]
    pub fn new(name: Option<String>, comment: Option<String>) -> Self {
        Self {
            inner: std::sync::Mutex::new(InnerRule::new_with_options(
                name.as_deref(),
                comment.as_deref(),
            )),
        }
    }

    pub fn name(&self) -> String {
        self.inner.lock().unwrap().name().to_string()
    }

    pub fn comment(&self) -> Option<String> {
        self.inner
            .lock()
            .unwrap()
            .comment()
            .map(ToString::to_string)
    }

    pub fn comment_set(&self, value: String) {
        self.inner.lock().unwrap().comment_set(&value);
    }

    pub fn comment_clear(&self) {
        self.inner.lock().unwrap().comment_clear();
    }

    pub fn check(&self) -> bool {
        self.inner.lock().unwrap().check()
    }

    pub fn meta(&self, key: String, value: &Bound<'_, PyAny>) -> PyResult<()> {
        let value = py_meta_value(value)?;
        self.inner.lock().unwrap().meta(&key, value);
        Ok(())
    }

    pub fn meta_set(&self, key: String, value: &Bound<'_, PyAny>) -> PyResult<()> {
        let value = py_meta_value(value)?;
        self.inner.lock().unwrap().meta_set(&key, value);
        Ok(())
    }

    pub fn meta_remove(&self, key: String) -> bool {
        self.inner.lock().unwrap().meta_remove(&key)
    }

    pub fn meta_clear(&self) {
        self.inner.lock().unwrap().meta_clear();
    }

    pub fn metadata(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let values = self
            .inner
            .lock()
            .unwrap()
            .metadata()
            .iter()
            .map(|(key, value)| (key.clone(), meta_value_to_pyobject(py, value)))
            .collect::<Vec<_>>();
        Ok(values.into_pyobject(py)?.unbind().into_any())
    }

    #[pyo3(signature = (pattern, comment=None))]
    pub fn pattern(&self, pattern: String, comment: Option<String>) {
        self.inner
            .lock()
            .unwrap()
            .pattern(&pattern, comment.as_deref());
    }

    #[pyo3(signature = (pattern, comment=None))]
    pub fn pattern_add(&self, pattern: String, comment: Option<String>) -> String {
        self.inner
            .lock()
            .unwrap()
            .pattern_add(&pattern, comment.as_deref())
    }

    #[pyo3(signature = (text, ascii=true, wide=false, comment=None))]
    pub fn text_add(
        &self,
        text: String,
        ascii: bool,
        wide: bool,
        comment: Option<String>,
    ) -> String {
        self.inner
            .lock()
            .unwrap()
            .text_add(&text, ascii, wide, comment.as_deref())
    }

    #[pyo3(signature = (regex, comment=None))]
    pub fn regex_add(&self, regex: String, comment: Option<String>) -> String {
        self.inner
            .lock()
            .unwrap()
            .regex_add(&regex, comment.as_deref())
    }

    #[pyo3(signature = (value, comment=None))]
    pub fn string_add(&self, value: String, comment: Option<String>) -> String {
        self.inner
            .lock()
            .unwrap()
            .string_add(&value, comment.as_deref())
    }

    pub fn pattern_update(
        &self,
        name: String,
        pattern: Option<String>,
        comment: Option<Option<String>>,
    ) -> bool {
        self.inner.lock().unwrap().pattern_update(
            &name,
            pattern.as_deref(),
            comment.as_ref().map(|comment| comment.as_deref()),
        )
    }

    pub fn remove(&self, name: String) -> bool {
        self.inner.lock().unwrap().remove(&name)
    }

    pub fn pattern_clear(&self) {
        self.inner.lock().unwrap().pattern_clear();
    }

    pub fn patterns(&self) -> Vec<Pattern> {
        self.inner
            .lock()
            .unwrap()
            .patterns()
            .iter()
            .cloned()
            .map(|inner| Pattern { inner })
            .collect()
    }

    pub fn condition(&self, value: String) {
        self.inner.lock().unwrap().condition(&value);
    }

    pub fn condition_clear(&self) {
        self.inner.lock().unwrap().condition_clear();
    }

    pub fn condition_value(&self) -> Option<String> {
        self.inner
            .lock()
            .unwrap()
            .condition_value()
            .map(ToString::to_string)
    }

    pub fn condition_all_of_them(&self) {
        self.inner.lock().unwrap().condition_all_of_them();
    }

    pub fn condition_number_of_them(&self, n: usize) {
        self.inner.lock().unwrap().condition_number_of_them(n);
    }

    pub fn condition_any_of(&self, names: Vec<String>) {
        self.inner.lock().unwrap().condition_any_of(&names);
    }

    pub fn condition_all_of(&self, names: Vec<String>) {
        self.inner.lock().unwrap().condition_all_of(&names);
    }

    pub fn condition_at_least(&self, n: usize, names: Vec<String>) {
        self.inner.lock().unwrap().condition_at_least(n, &names);
    }

    pub fn render(&self) -> String {
        self.inner.lock().unwrap().render()
    }

    pub fn print(&self) {
        self.inner.lock().unwrap().print();
    }

    pub fn write(&self, path: String) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .write(path)
            .map_err(|error| PyIOError::new_err(error.to_string()))
    }

    pub fn compile(&self) -> PyResult<CompiledRuleSet> {
        let compiled = self
            .inner
            .lock()
            .unwrap()
            .compile()
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(CompiledRuleSet {
            inner: std::sync::Mutex::new(compiled),
        })
    }

    pub fn scan(&self, data: Vec<u8>) -> PyResult<ScanResults> {
        let results = self
            .inner
            .lock()
            .unwrap()
            .scan(&data)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(ScanResults { inner: results })
    }

    pub fn scan_file(&self, path: String) -> PyResult<ScanResults> {
        let results = self
            .inner
            .lock()
            .unwrap()
            .scan_file(path)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(ScanResults { inner: results })
    }

    fn __str__(&self) -> String {
        self.render()
    }
}

fn py_meta_value(value: &Bound<'_, PyAny>) -> PyResult<InnerMetaValue> {
    if let Ok(value) = value.extract::<bool>() {
        return Ok(value.into());
    }
    if let Ok(value) = value.extract::<i64>() {
        return Ok(value.into());
    }
    if let Ok(value) = value.extract::<f64>() {
        return Ok(value.into());
    }
    if let Ok(value) = value.extract::<String>() {
        return Ok(value.into());
    }
    Err(PyTypeError::new_err(
        "metadata values must be str, int, float, or bool",
    ))
}

#[pymodule]
pub fn yara_init(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Pattern>()?;
    m.add_class::<Rule>()?;
    m.add_class::<RuleMatch>()?;
    m.add_class::<ScanResults>()?;
    m.add_class::<CompiledRuleSet>()?;
    m.add_class::<RuleSet>()?;
    Ok(())
}

fn meta_value_to_pyobject(py: Python<'_>, value: &InnerMetaValue) -> Py<PyAny> {
    match value {
        InnerMetaValue::String(value) => {
            value.clone().into_pyobject(py).unwrap().unbind().into_any()
        }
        InnerMetaValue::Integer(value) => (*value).into_pyobject(py).unwrap().unbind().into_any(),
        InnerMetaValue::Float(value) => (*value).into_pyobject(py).unwrap().unbind().into_any(),
        InnerMetaValue::Boolean(value) => PyBool::new(py, *value).to_owned().unbind().into_any(),
    }
}
