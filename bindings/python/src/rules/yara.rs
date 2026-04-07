use pyo3::exceptions::{PyIOError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyAny;
use pyo3::types::PyBool;

use ::binlex::rules::{
    YARACompiledRuleSet as InnerCompiledRuleSet, YARACondition as InnerCondition,
    YARAMatch as InnerYARAMatch, YARAMetaValue as InnerMetaValue, YARAPattern as InnerPattern,
    YARAPatternKind as InnerPatternKind, YARARule as InnerRule, YARARuleSet as InnerRuleSet,
    YARAScanResults as InnerYARAScanResults,
};

#[pyclass(name = "Pattern", skip_from_py_object)]
#[derive(Clone)]
pub struct Pattern {
    inner: InnerPattern,
}

#[pymethods]
impl Pattern {
    pub fn get_name(&self) -> String {
        self.inner.name.clone()
    }

    pub fn get_pattern(&self) -> String {
        self.inner.value.clone()
    }

    pub fn get_comment(&self) -> Option<String> {
        self.inner.comment.clone()
    }

    pub fn get_kind(&self) -> String {
        match self.inner.kind {
            InnerPatternKind::Hex => "hex".to_string(),
            InnerPatternKind::Text => "text".to_string(),
            InnerPatternKind::Regex => "regex".to_string(),
            InnerPatternKind::String => "string".to_string(),
        }
    }

    pub fn is_ascii(&self) -> bool {
        self.inner.ascii
    }

    pub fn is_wide(&self) -> bool {
        self.inner.wide
    }
}

#[pyclass(name = "Rule")]
pub struct Rule {
    inner: std::sync::Mutex<InnerRule>,
}

#[pyclass(name = "Condition", skip_from_py_object)]
#[derive(Clone)]
pub struct Condition {
    inner: InnerCondition,
}

#[pymethods]
impl Condition {
    fn __str__(&self) -> String {
        self.inner.render()
    }
}

#[pyclass(name = "YARAMatch", skip_from_py_object)]
#[derive(Clone)]
pub struct YARAMatch {
    inner: InnerYARAMatch,
}

#[pymethods]
impl YARAMatch {
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

#[pyclass(name = "YARAScanResults")]
pub struct YARAScanResults {
    inner: InnerYARAScanResults,
}

#[pymethods]
impl YARAScanResults {
    pub fn get_matches(&self) -> Vec<YARAMatch> {
        self.inner
            .get_matches()
            .iter()
            .cloned()
            .map(|inner| YARAMatch { inner })
            .collect()
    }
}

#[pyclass(name = "CompiledRuleSet")]
pub struct CompiledRuleSet {
    inner: std::sync::Mutex<InnerCompiledRuleSet>,
}

#[pymethods]
impl CompiledRuleSet {
    pub fn scan(&self, data: Vec<u8>) -> PyResult<YARAScanResults> {
        let results = self
            .inner
            .lock()
            .unwrap()
            .scan(&data)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(YARAScanResults { inner: results })
    }

    pub fn scan_file(&self, path: String) -> PyResult<YARAScanResults> {
        let results = self
            .inner
            .lock()
            .unwrap()
            .scan_file(path)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(YARAScanResults { inner: results })
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

    pub fn get_rules(&self) -> Vec<Rule> {
        self.inner
            .lock()
            .unwrap()
            .get_rules()
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

    pub fn scan(&self, data: Vec<u8>) -> PyResult<YARAScanResults> {
        let results = self
            .inner
            .lock()
            .unwrap()
            .scan(&data)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(YARAScanResults { inner: results })
    }

    pub fn scan_file(&self, path: String) -> PyResult<YARAScanResults> {
        let results = self
            .inner
            .lock()
            .unwrap()
            .scan_file(path)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(YARAScanResults { inner: results })
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

    pub fn get_name(&self) -> String {
        self.inner.lock().unwrap().get_name().to_string()
    }

    pub fn get_comment(&self) -> Option<String> {
        self.inner
            .lock()
            .unwrap()
            .get_comment()
            .map(ToString::to_string)
    }

    pub fn add_import(&self, value: String) {
        self.inner.lock().unwrap().add_import(&value);
    }

    pub fn remove_import(&self, value: String) -> bool {
        self.inner.lock().unwrap().remove_import(&value)
    }

    pub fn clear_imports(&self) {
        self.inner.lock().unwrap().clear_imports();
    }

    pub fn add_tag(&self, value: String) {
        self.inner.lock().unwrap().add_tag(&value);
    }

    pub fn remove_tag(&self, value: String) -> bool {
        self.inner.lock().unwrap().remove_tag(&value)
    }

    pub fn clear_tags(&self) {
        self.inner.lock().unwrap().clear_tags();
    }

    #[pyo3(signature = (value=true))]
    pub fn set_global(&self, value: bool) {
        self.inner.lock().unwrap().set_global(value);
    }

    #[pyo3(signature = (value=true))]
    pub fn set_private(&self, value: bool) {
        self.inner.lock().unwrap().set_private(value);
    }

    pub fn is_global(&self) -> bool {
        self.inner.lock().unwrap().is_global()
    }

    pub fn is_private(&self) -> bool {
        self.inner.lock().unwrap().is_private()
    }

    pub fn set_comment(&self, value: String) {
        self.inner.lock().unwrap().set_comment(&value);
    }

    pub fn clear_comment(&self) {
        self.inner.lock().unwrap().clear_comment();
    }

    pub fn check(&self) -> bool {
        self.inner.lock().unwrap().check()
    }

    pub fn set_metadata(&self, key: String, value: &Bound<'_, PyAny>) -> PyResult<()> {
        let value = py_meta_value(value)?;
        self.inner.lock().unwrap().set_metadata(&key, value);
        Ok(())
    }

    pub fn remove_metadata(&self, key: String) -> bool {
        self.inner.lock().unwrap().remove_metadata(&key)
    }

    pub fn clear_metadata(&self) {
        self.inner.lock().unwrap().clear_metadata();
    }

    pub fn get_metadata(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let values = self
            .inner
            .lock()
            .unwrap()
            .get_metadata()
            .iter()
            .map(|(key, value)| (key.clone(), meta_value_to_pyobject(py, value)))
            .collect::<Vec<_>>();
        Ok(values.into_pyobject(py)?.unbind().into_any())
    }

    #[pyo3(signature = (pattern, comment=None))]
    pub fn add_pattern(&self, pattern: String, comment: Option<String>) -> String {
        self.inner
            .lock()
            .unwrap()
            .add_pattern(&pattern, comment.as_deref())
    }

    #[pyo3(signature = (name, parts, destructive=true))]
    pub fn fragment_pattern(
        &self,
        name: String,
        parts: usize,
        destructive: bool,
    ) -> PyResult<Vec<String>> {
        self.inner
            .lock()
            .unwrap()
            .fragment_pattern(&name, parts, destructive)
            .map_err(|error| PyValueError::new_err(error.to_string()))
    }

    #[pyo3(signature = (
        text,
        ascii=true,
        wide=false,
        nocase=false,
        xor=false,
        base64=false,
        base64wide=false,
        fullword=false,
        private=false,
        comment=None
    ))]
    pub fn add_text(
        &self,
        text: String,
        ascii: bool,
        wide: bool,
        nocase: bool,
        xor: bool,
        base64: bool,
        base64wide: bool,
        fullword: bool,
        private: bool,
        comment: Option<String>,
    ) -> PyResult<String> {
        self.inner
            .lock()
            .unwrap()
            .add_text(
                &text,
                ascii,
                wide,
                nocase,
                xor,
                base64,
                base64wide,
                fullword,
                private,
                comment.as_deref(),
            )
            .map_err(|error| PyValueError::new_err(error.to_string()))
    }

    #[pyo3(signature = (regex, comment=None))]
    pub fn add_regex(&self, regex: String, comment: Option<String>) -> String {
        self.inner
            .lock()
            .unwrap()
            .add_regex(&regex, comment.as_deref())
    }

    #[pyo3(signature = (value, comment=None))]
    pub fn add_string(&self, value: String, comment: Option<String>) -> String {
        self.inner
            .lock()
            .unwrap()
            .add_string(&value, comment.as_deref())
    }

    pub fn update_pattern(
        &self,
        name: String,
        pattern: Option<String>,
        comment: Option<Option<String>>,
    ) -> bool {
        self.inner.lock().unwrap().update_pattern(
            &name,
            pattern.as_deref(),
            comment.as_ref().map(|comment| comment.as_deref()),
        )
    }

    pub fn remove_pattern(&self, name: String) -> bool {
        self.inner.lock().unwrap().remove_pattern(&name)
    }

    pub fn clear_patterns(&self) {
        self.inner.lock().unwrap().clear_patterns();
    }

    pub fn get_patterns(&self) -> Vec<Pattern> {
        self.inner
            .lock()
            .unwrap()
            .get_patterns()
            .iter()
            .cloned()
            .map(|inner| Pattern { inner })
            .collect()
    }

    pub fn condition(&self, value: String) -> Condition {
        Condition {
            inner: self.inner.lock().unwrap().condition(value),
        }
    }

    pub fn condition_at_least(&self, minimum: usize, patterns: Vec<String>) -> Condition {
        Condition {
            inner: self
                .inner
                .lock()
                .unwrap()
                .condition_at_least(minimum, patterns),
        }
    }

    pub fn condition_and(&self, values: Vec<PyRef<'_, Condition>>) -> Condition {
        Condition {
            inner: self.inner.lock().unwrap().condition_and(
                values
                    .into_iter()
                    .map(|value| value.inner.clone())
                    .collect(),
            ),
        }
    }

    pub fn condition_or(&self, values: Vec<PyRef<'_, Condition>>) -> Condition {
        Condition {
            inner: self.inner.lock().unwrap().condition_or(
                values
                    .into_iter()
                    .map(|value| value.inner.clone())
                    .collect(),
            ),
        }
    }

    pub fn condition_not(&self, value: &Condition) -> Condition {
        Condition {
            inner: self
                .inner
                .lock()
                .unwrap()
                .condition_not(value.inner.clone()),
        }
    }

    pub fn set_condition(&self, value: &Condition) {
        self.inner
            .lock()
            .unwrap()
            .set_condition(value.inner.clone());
    }

    pub fn add_condition(&self, value: &Condition) {
        self.inner
            .lock()
            .unwrap()
            .add_condition(value.inner.clone());
    }

    pub fn clear_condition(&self) {
        self.inner.lock().unwrap().clear_condition();
    }

    pub fn get_condition(&self) -> Option<Condition> {
        self.inner
            .lock()
            .unwrap()
            .get_condition()
            .cloned()
            .map(|inner| Condition { inner })
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

    pub fn scan(&self, data: Vec<u8>) -> PyResult<YARAScanResults> {
        let results = self
            .inner
            .lock()
            .unwrap()
            .scan(&data)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(YARAScanResults { inner: results })
    }

    pub fn scan_file(&self, path: String) -> PyResult<YARAScanResults> {
        let results = self
            .inner
            .lock()
            .unwrap()
            .scan_file(path)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(YARAScanResults { inner: results })
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
#[pyo3(name = "rules")]
pub fn rules_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Pattern>()?;
    m.add_class::<Rule>()?;
    m.add_class::<Condition>()?;
    m.add_class::<YARAMatch>()?;
    m.add_class::<YARAScanResults>()?;
    m.add_class::<CompiledRuleSet>()?;
    m.add_class::<RuleSet>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.rules", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.rules")?;
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
