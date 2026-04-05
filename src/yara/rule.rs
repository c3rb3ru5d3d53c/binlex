use chrono::Utc;
use std::fmt;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use yara_x::ScanError;
use yara_x::errors::CompileError;

#[derive(Debug, Clone, PartialEq)]
pub enum MetaValue {
    String(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
}

impl From<String> for MetaValue {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<&str> for MetaValue {
    fn from(value: &str) -> Self {
        Self::String(value.to_string())
    }
}

impl From<i64> for MetaValue {
    fn from(value: i64) -> Self {
        Self::Integer(value)
    }
}

impl From<i32> for MetaValue {
    fn from(value: i32) -> Self {
        Self::Integer(value as i64)
    }
}

impl From<u64> for MetaValue {
    fn from(value: u64) -> Self {
        Self::Integer(value as i64)
    }
}

impl From<u32> for MetaValue {
    fn from(value: u32) -> Self {
        Self::Integer(value as i64)
    }
}

impl From<f64> for MetaValue {
    fn from(value: f64) -> Self {
        Self::Float(value)
    }
}

impl From<f32> for MetaValue {
    fn from(value: f32) -> Self {
        Self::Float(value as f64)
    }
}

impl From<bool> for MetaValue {
    fn from(value: bool) -> Self {
        Self::Boolean(value)
    }
}

impl fmt::Display for MetaValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::String(value) => write!(f, "\"{}\"", escape_yara_string(value)),
            Self::Integer(value) => write!(f, "{value}"),
            Self::Float(value) => write!(f, "{value}"),
            Self::Boolean(value) => write!(f, "{value}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Pattern {
    pub name: String,
    pub value: String,
    pub comment: Option<String>,
    pub kind: PatternKind,
    pub ascii: bool,
    pub wide: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternKind {
    Hex,
    Text,
    Regex,
    String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rule {
    name: String,
    comment: Option<String>,
    metadata: Vec<(String, MetaValue)>,
    patterns: Vec<Pattern>,
    condition: Option<String>,
    next_pattern_index: usize,
    next_text_index: usize,
    next_regex_index: usize,
    next_string_index: usize,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct RuleSet {
    rules: Vec<Rule>,
}

#[derive(Clone)]
pub struct CompiledRuleSet {
    rules: Arc<yara_x::Rules>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RuleMatch {
    rule: String,
    offset: usize,
    data: Vec<u8>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ScanResults {
    matches: Vec<RuleMatch>,
}

#[derive(Debug)]
pub enum Error {
    Compile(CompileError),
    Scan(ScanError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Compile(error) => write!(f, "{error}"),
            Self::Scan(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<CompileError> for Error {
    fn from(value: CompileError) -> Self {
        Self::Compile(value)
    }
}

impl From<ScanError> for Error {
    fn from(value: ScanError) -> Self {
        Self::Scan(value)
    }
}

impl Default for Rule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule {
    pub fn new() -> Self {
        Self::new_with_options(None, None)
    }

    pub fn new_with_options(name: Option<&str>, comment: Option<&str>) -> Self {
        Self {
            name: name
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
                .unwrap_or_else(default_rule_name),
            comment: comment
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string),
            metadata: Vec::new(),
            patterns: Vec::new(),
            condition: None,
            next_pattern_index: 0,
            next_text_index: 0,
            next_regex_index: 0,
            next_string_index: 0,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }

    pub fn comment_set(&mut self, value: &str) -> &mut Self {
        self.comment = Some(value.trim().to_string());
        self
    }

    pub fn comment_clear(&mut self) -> &mut Self {
        self.comment = None;
        self
    }

    pub fn check(&self) -> bool {
        self.compile().is_ok()
    }

    pub fn meta<V>(&mut self, key: &str, value: V) -> &mut Self
    where
        V: Into<MetaValue>,
    {
        self.meta_set(key, value);
        self
    }

    pub fn meta_set<V>(&mut self, key: &str, value: V) -> &mut Self
    where
        V: Into<MetaValue>,
    {
        let key = key.trim().to_string();
        let value = value.into();
        if let Some((_, existing)) = self
            .metadata
            .iter_mut()
            .find(|(existing, _)| *existing == key)
        {
            *existing = value;
        } else {
            self.metadata.push((key, value));
        }
        self
    }

    pub fn meta_remove(&mut self, key: &str) -> bool {
        let before = self.metadata.len();
        self.metadata.retain(|(existing, _)| existing != key.trim());
        self.metadata.len() != before
    }

    pub fn meta_clear(&mut self) -> &mut Self {
        self.metadata.clear();
        self
    }

    pub fn metadata(&self) -> &[(String, MetaValue)] {
        &self.metadata
    }

    pub fn pattern(&mut self, pattern: &str, comment: Option<&str>) -> &mut Self {
        self.pattern_add(pattern, comment);
        self
    }

    pub fn pattern_add(&mut self, pattern: &str, comment: Option<&str>) -> String {
        let name = format!("$chromosome_{}", self.next_pattern_index);
        self.next_pattern_index += 1;
        self.patterns.push(Pattern {
            name: name.clone(),
            value: pattern.trim().to_string(),
            comment: comment
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string),
            kind: PatternKind::Hex,
            ascii: false,
            wide: false,
        });
        name
    }

    pub fn text_add(
        &mut self,
        text: &str,
        ascii: bool,
        wide: bool,
        comment: Option<&str>,
    ) -> String {
        let name = format!("$text_{}", self.next_text_index);
        self.next_text_index += 1;
        self.patterns.push(Pattern {
            name: name.clone(),
            value: text.to_string(),
            comment: comment
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string),
            kind: PatternKind::Text,
            ascii,
            wide,
        });
        name
    }

    pub fn regex_add(&mut self, regex: &str, comment: Option<&str>) -> String {
        let name = format!("$regex_{}", self.next_regex_index);
        self.next_regex_index += 1;
        self.patterns.push(Pattern {
            name: name.clone(),
            value: regex.to_string(),
            comment: comment
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string),
            kind: PatternKind::Regex,
            ascii: false,
            wide: false,
        });
        name
    }

    pub fn string_add(&mut self, value: &str, comment: Option<&str>) -> String {
        let name = format!("$string_{}", self.next_string_index);
        self.next_string_index += 1;
        self.patterns.push(Pattern {
            name: name.clone(),
            value: value.trim().to_string(),
            comment: comment
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string),
            kind: PatternKind::String,
            ascii: false,
            wide: false,
        });
        name
    }

    pub fn pattern_update(
        &mut self,
        name: &str,
        pattern: Option<&str>,
        comment: Option<Option<&str>>,
    ) -> bool {
        let Some(existing) = self
            .patterns
            .iter_mut()
            .find(|existing| existing.name == name.trim())
        else {
            return false;
        };
        if let Some(pattern) = pattern {
            existing.value = pattern.trim().to_string();
        }
        if let Some(comment) = comment {
            existing.comment = comment
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string);
        }
        true
    }

    pub fn remove(&mut self, name: &str) -> bool {
        let before = self.patterns.len();
        self.patterns
            .retain(|existing| existing.name != name.trim());
        self.patterns.len() != before
    }

    pub fn pattern_clear(&mut self) -> &mut Self {
        self.patterns.clear();
        self
    }

    pub fn patterns(&self) -> &[Pattern] {
        &self.patterns
    }

    pub fn condition(&mut self, value: &str) -> &mut Self {
        self.condition = Some(value.trim().to_string());
        self
    }

    pub fn condition_clear(&mut self) -> &mut Self {
        self.condition = None;
        self
    }

    pub fn condition_value(&self) -> Option<&str> {
        self.condition.as_deref()
    }

    pub fn condition_all_of_them(&mut self) -> &mut Self {
        self.condition("all of them")
    }

    pub fn condition_number_of_them(&mut self, n: usize) -> &mut Self {
        self.condition(&format!("{n} of them"))
    }

    pub fn condition_any_of<S>(&mut self, names: &[S]) -> &mut Self
    where
        S: AsRef<str>,
    {
        self.condition(&format!("any of ({})", format_names(names)))
    }

    pub fn condition_all_of<S>(&mut self, names: &[S]) -> &mut Self
    where
        S: AsRef<str>,
    {
        self.condition(&format!("all of ({})", format_names(names)))
    }

    pub fn condition_at_least<S>(&mut self, n: usize, names: &[S]) -> &mut Self
    where
        S: AsRef<str>,
    {
        self.condition(&format!("{n} of ({})", format_names(names)))
    }

    pub fn render(&self) -> String {
        let mut output = String::new();
        if let Some(comment) = &self.comment {
            output.push_str(&format!("// {}\n", comment));
        }
        output.push_str(&format!("rule {} {{\n", self.name));

        if !self.metadata.is_empty() {
            output.push_str("  meta:\n");
            for (key, value) in &self.metadata {
                output.push_str(&format!("    {} = {}\n", key, value));
            }
            output.push('\n');
        }

        if !self.patterns.is_empty() {
            output.push_str("  strings:\n");
            for (index, pattern) in self.patterns.iter().enumerate() {
                if let Some(comment) = &pattern.comment {
                    output.push_str(&format!("    // {}\n", comment));
                }
                output.push_str(&format!(
                    "    {} = {}\n",
                    pattern.name,
                    render_pattern(pattern)
                ));
                if index + 1 != self.patterns.len() {
                    output.push('\n');
                }
            }
            output.push('\n');
        }

        output.push_str("  condition:\n");
        output.push_str(&format!(
            "    {}\n",
            self.condition.as_deref().unwrap_or("all of them")
        ));
        output.push('}');
        output
    }

    pub fn print(&self) {
        println!("{}", self.render());
    }

    pub fn write(&self, path: impl AsRef<Path>) -> std::io::Result<()> {
        fs::write(path, self.render())
    }

    pub fn compile(&self) -> Result<CompiledRuleSet, Error> {
        let mut rules = RuleSet::new();
        rules.add(self.clone());
        rules.compile()
    }

    pub fn scan(&self, data: &[u8]) -> Result<ScanResults, Error> {
        self.compile()?.scan(data)
    }

    pub fn scan_file(&self, path: impl AsRef<Path>) -> Result<ScanResults, Error> {
        self.compile()?.scan_file(path)
    }
}

impl RuleSet {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn add(&mut self, rule: Rule) -> &mut Self {
        self.remove(rule.name());
        self.rules.push(rule);
        self
    }

    pub fn remove(&mut self, name: &str) -> bool {
        let before = self.rules.len();
        self.rules.retain(|rule| rule.name() != name.trim());
        self.rules.len() != before
    }

    pub fn clear(&mut self) -> &mut Self {
        self.rules.clear();
        self
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    pub fn check(&self) -> bool {
        self.compile().is_ok()
    }

    pub fn compile(&self) -> Result<CompiledRuleSet, Error> {
        let mut compiler = yara_x::Compiler::new();
        for rule in &self.rules {
            let rendered = rule.render();
            compiler.add_source(rendered.as_str())?;
        }
        let rules = compiler.build();
        Ok(CompiledRuleSet {
            rules: Arc::new(rules),
        })
    }

    pub fn scan(&self, data: &[u8]) -> Result<ScanResults, Error> {
        self.compile()?.scan(data)
    }

    pub fn scan_file(&self, path: impl AsRef<Path>) -> Result<ScanResults, Error> {
        self.compile()?.scan_file(path)
    }
}

impl CompiledRuleSet {
    pub fn scan(&self, data: &[u8]) -> Result<ScanResults, Error> {
        let mut scanner = yara_x::Scanner::new(&self.rules);
        let results = scanner.scan(data)?;
        Ok(scan_results_from_yara_x(results))
    }

    pub fn scan_file(&self, path: impl AsRef<Path>) -> Result<ScanResults, Error> {
        let mut scanner = yara_x::Scanner::new(&self.rules);
        let results = scanner.scan_file(path)?;
        Ok(scan_results_from_yara_x(results))
    }
}

impl RuleMatch {
    pub fn rule(&self) -> &str {
        &self.rule
    }

    pub fn offset(&self) -> usize {
        self.offset
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn size(&self) -> usize {
        self.data.len()
    }
}

impl ScanResults {
    pub fn matches(&self) -> &[RuleMatch] {
        &self.matches
    }
}

impl IntoIterator for ScanResults {
    type Item = RuleMatch;
    type IntoIter = std::vec::IntoIter<RuleMatch>;

    fn into_iter(self) -> Self::IntoIter {
        self.matches.into_iter()
    }
}

impl<'a> IntoIterator for &'a ScanResults {
    type Item = &'a RuleMatch;
    type IntoIter = std::slice::Iter<'a, RuleMatch>;

    fn into_iter(self) -> Self::IntoIter {
        self.matches.iter()
    }
}

fn default_rule_name() -> String {
    format!("binlex_{}", Utc::now().format("%Y_%m_%dT%H_%M_%SZ"))
}

fn escape_yara_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn escape_yara_regex(value: &str) -> String {
    value.replace('\\', "\\\\").replace('/', "\\/")
}

fn format_names<S>(names: &[S]) -> String
where
    S: AsRef<str>,
{
    names
        .iter()
        .map(|name| name.as_ref().trim().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

fn render_pattern(pattern: &Pattern) -> String {
    match pattern.kind {
        PatternKind::Hex => format!("{{ {} }}", pattern.value),
        PatternKind::Text => {
            let mut rendered = format!("\"{}\"", escape_yara_string(&pattern.value));
            if pattern.ascii {
                rendered.push_str(" ascii");
            }
            if pattern.wide {
                rendered.push_str(" wide");
            }
            rendered
        }
        PatternKind::Regex => format!("/{}/", escape_yara_regex(&pattern.value)),
        PatternKind::String => pattern.value.clone(),
    }
}

fn scan_results_from_yara_x(results: yara_x::ScanResults<'_, '_>) -> ScanResults {
    let mut matches = Vec::new();
    for matching_rule in results.matching_rules() {
        for pattern in matching_rule.patterns() {
            for matched in pattern.matches() {
                matches.push(RuleMatch {
                    rule: matching_rule.identifier().to_string(),
                    offset: matched.range().start,
                    data: matched.data().to_vec(),
                });
            }
        }
    }
    ScanResults { matches }
}

#[cfg(test)]
mod tests {
    use super::{Rule, RuleSet};

    #[test]
    fn rule_defaults_name_and_all_of_them_condition() {
        let mut rule = Rule::new();
        rule.meta("author", "analyst");
        rule.pattern("55 8B EC ??", Some("prologue"));
        let text = rule.render();
        assert!(text.contains("rule binlex_"));
        assert!(text.contains("author = \"analyst\""));
        assert!(text.contains("// prologue"));
        assert!(text.contains("$chromosome_0 = { 55 8B EC ?? }"));
        assert!(text.contains("condition:\n    all of them"));
    }

    #[test]
    fn rule_supports_number_of_them_condition() {
        let mut rule = Rule::new_with_options(Some("dispatcher_like"), None);
        rule.pattern("AA BB CC", None);
        rule.pattern("DD EE FF", None);
        rule.condition_number_of_them(2);
        let text = rule.render();
        assert!(text.contains("rule dispatcher_like"));
        assert!(text.contains("condition:\n    2 of them"));
    }

    #[test]
    fn rule_supports_metadata_replacement_and_removal() {
        let mut rule = Rule::new_with_options(Some("meta_test"), None);
        rule.meta_set("author", "analyst");
        rule.meta_set("author", "researcher");
        rule.meta_set("score", 10);
        assert_eq!(rule.metadata().len(), 2);
        assert!(rule.meta_remove("score"));
        assert_eq!(rule.metadata().len(), 1);
        assert_eq!(rule.metadata()[0].0, "author");
    }

    #[test]
    fn rule_supports_named_pattern_mutation() {
        let mut rule = Rule::new_with_options(Some("pattern_test"), None);
        let first = rule.pattern_add("AA BB", Some("first"));
        let second = rule.pattern_add("CC DD", None);
        assert_eq!(first, "$chromosome_0");
        assert_eq!(second, "$chromosome_1");
        assert!(rule.pattern_update(&second, Some("EE FF"), Some(Some("updated"))));
        assert!(rule.remove(&first));
        let text = rule.render();
        assert!(!text.contains("$chromosome_0 ="));
        assert!(text.contains("$chromosome_1 = { EE FF }"));
        assert!(text.contains("// updated"));
    }

    #[test]
    fn rule_supports_condition_clear() {
        let mut rule = Rule::new_with_options(Some("condition_test"), None);
        rule.condition("1 of them");
        assert_eq!(rule.condition_value(), Some("1 of them"));
        rule.condition_clear();
        assert_eq!(rule.condition_value(), None);
        assert!(rule.render().contains("condition:\n    all of them"));
    }

    #[test]
    fn rule_can_check_and_scan() {
        let mut rule = Rule::new_with_options(Some("scan_test"), None);
        rule.pattern_add("61 62 63", Some("abc"));
        rule.condition_all_of_them();
        assert!(rule.check());
        let results = rule.scan(b"abc").unwrap();
        assert_eq!(results.matches().len(), 1);
        assert_eq!(results.matches()[0].rule(), "scan_test");
        assert_eq!(results.matches()[0].offset(), 0);
        assert_eq!(results.matches()[0].data(), b"abc");
        assert_eq!(results.matches()[0].size(), 3);
    }

    #[test]
    fn rule_supports_text_regex_and_named_conditions() {
        let mut rule = Rule::new_with_options(Some("hybrid"), None);
        let chromosome = rule.pattern_add("61 62 63", Some("hex"));
        let text = rule.text_add("powershell", true, true, Some("text"));
        let regex = rule.regex_add(r"https?://example\.com", Some("regex"));
        let custom = rule.string_add("xor wide ascii \"cmd.exe\"", Some("custom"));
        rule.condition_at_least(
            2,
            &[
                chromosome.clone(),
                text.clone(),
                regex.clone(),
                custom.clone(),
            ],
        );
        let rendered = rule.render();
        assert!(rendered.contains("$text_0 = \"powershell\" ascii wide"));
        assert!(rendered.contains(r#"$regex_0 = /https?:\/\/example\\.com/"#));
        assert!(rendered.contains("$string_0 = xor wide ascii \"cmd.exe\""));
        assert!(rendered.contains(&format!(
            "condition:\n    2 of ({}, {}, {}, {})",
            chromosome, text, regex, custom
        )));
    }

    #[test]
    fn rule_supports_constructor_comment() {
        let mut rule = Rule::new_with_options(Some("commented"), Some("generated from binlex"));
        rule.pattern_add("AA BB", None);
        let rendered = rule.render();
        assert!(rendered.starts_with("// generated from binlex\nrule commented {"));
    }

    #[test]
    fn ruleset_can_scan_multiple_rules() {
        let mut first = Rule::new_with_options(Some("first"), None);
        first.pattern_add("61 62 63", None);
        first.condition_all_of_them();

        let mut second = Rule::new_with_options(Some("second"), None);
        second.pattern_add("64 65 66", None);
        second.condition_all_of_them();

        let mut rules = RuleSet::new();
        rules.add(first);
        rules.add(second);

        assert!(rules.check());
        let results = rules.scan(b"abcdef").unwrap();
        let names = results
            .matches()
            .iter()
            .map(|matched| matched.rule().to_string())
            .collect::<Vec<_>>();
        assert!(names.contains(&"first".to_string()));
        assert!(names.contains(&"second".to_string()));
    }
}
