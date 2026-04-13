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
    pub nocase: bool,
    pub xor: bool,
    pub base64: bool,
    pub base64wide: bool,
    pub fullword: bool,
    pub private: bool,
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
    imports: Vec<String>,
    tags: Vec<String>,
    global: bool,
    private: bool,
    comment: Option<String>,
    metadata: Vec<(String, MetaValue)>,
    patterns: Vec<Pattern>,
    condition: Option<Condition>,
    next_pattern_index: usize,
    next_text_index: usize,
    next_regex_index: usize,
    next_string_index: usize,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct RuleSet {
    rules: Vec<Rule>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Condition {
    Raw(String),
    And(Vec<Condition>),
    Or(Vec<Condition>),
    Not(Box<Condition>),
}

#[derive(Clone)]
pub struct CompiledRuleSet {
    rules: Arc<yara_x::Rules>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Match {
    rule: String,
    offset: usize,
    data: Vec<u8>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ScanResults {
    matches: Vec<Match>,
}

#[derive(Debug)]
pub enum Error {
    Validation(String),
    Compile(CompileError),
    Scan(ScanError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation(error) => write!(f, "{error}"),
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

impl From<String> for Condition {
    fn from(value: String) -> Self {
        Self::Raw(value.trim().to_string())
    }
}

impl From<&str> for Condition {
    fn from(value: &str) -> Self {
        Self::Raw(value.trim().to_string())
    }
}

impl From<&String> for Condition {
    fn from(value: &String) -> Self {
        Self::Raw(value.trim().to_string())
    }
}

impl fmt::Display for Condition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.render())
    }
}

impl Condition {
    pub fn render(&self) -> String {
        match self {
            Self::Raw(value) => value.trim().to_string(),
            Self::And(parts) => render_condition_group("and", parts),
            Self::Or(parts) => render_condition_group("or", parts),
            Self::Not(part) => format!("not ({})", part.render()),
        }
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
            imports: Vec::new(),
            tags: Vec::new(),
            global: false,
            private: false,
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

    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn get_comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }

    pub fn add_import(&mut self, value: &str) -> &mut Self {
        let value = value.trim();
        if value.is_empty() {
            return self;
        }
        if !self.imports.iter().any(|existing| existing == value) {
            self.imports.push(value.to_string());
        }
        self
    }

    pub fn remove_import(&mut self, value: &str) -> bool {
        let before = self.imports.len();
        self.imports.retain(|existing| existing != value.trim());
        self.imports.len() != before
    }

    pub fn clear_imports(&mut self) -> &mut Self {
        self.imports.clear();
        self
    }

    pub fn add_tag(&mut self, value: &str) -> &mut Self {
        let value = value.trim();
        if value.is_empty() {
            return self;
        }
        if !self.tags.iter().any(|existing| existing == value) {
            self.tags.push(value.to_string());
        }
        self
    }

    pub fn remove_tag(&mut self, value: &str) -> bool {
        let before = self.tags.len();
        self.tags.retain(|existing| existing != value.trim());
        self.tags.len() != before
    }

    pub fn clear_tags(&mut self) -> &mut Self {
        self.tags.clear();
        self
    }

    pub fn set_global(&mut self, value: bool) -> &mut Self {
        self.global = value;
        self
    }

    pub fn set_private(&mut self, value: bool) -> &mut Self {
        self.private = value;
        self
    }

    pub fn is_global(&self) -> bool {
        self.global
    }

    pub fn is_private(&self) -> bool {
        self.private
    }

    pub fn set_comment(&mut self, value: &str) -> &mut Self {
        self.comment = Some(value.trim().to_string());
        self
    }

    pub fn clear_comment(&mut self) -> &mut Self {
        self.comment = None;
        self
    }

    pub fn check(&self) -> bool {
        self.compile().is_ok()
    }

    pub fn set_metadata<V>(&mut self, key: &str, value: V) -> &mut Self
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

    pub fn remove_metadata(&mut self, key: &str) -> bool {
        let before = self.metadata.len();
        self.metadata.retain(|(existing, _)| existing != key.trim());
        self.metadata.len() != before
    }

    pub fn clear_metadata(&mut self) -> &mut Self {
        self.metadata.clear();
        self
    }

    pub fn get_metadata(&self) -> &[(String, MetaValue)] {
        &self.metadata
    }

    pub fn add_pattern(&mut self, pattern: &str, comment: Option<&str>) -> String {
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
            nocase: false,
            xor: false,
            base64: false,
            base64wide: false,
            fullword: false,
            private: false,
        });
        name
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_text(
        &mut self,
        text: &str,
        ascii: bool,
        wide: bool,
        nocase: bool,
        xor: bool,
        base64: bool,
        base64wide: bool,
        fullword: bool,
        private: bool,
        comment: Option<&str>,
    ) -> Result<String, Error> {
        validate_text_modifiers(nocase, xor, base64, base64wide, fullword)?;
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
            nocase,
            xor,
            base64,
            base64wide,
            fullword,
            private,
        });
        Ok(name)
    }

    pub fn add_regex(&mut self, regex: &str, comment: Option<&str>) -> String {
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
            nocase: false,
            xor: false,
            base64: false,
            base64wide: false,
            fullword: false,
            private: false,
        });
        name
    }

    pub fn add_string(&mut self, value: &str, comment: Option<&str>) -> String {
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
            nocase: false,
            xor: false,
            base64: false,
            base64wide: false,
            fullword: false,
            private: false,
        });
        name
    }

    pub fn update_pattern(
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

    pub fn remove_pattern(&mut self, name: &str) -> bool {
        let before = self.patterns.len();
        self.patterns
            .retain(|existing| existing.name != name.trim());
        self.patterns.len() != before
    }

    pub fn clear_patterns(&mut self) -> &mut Self {
        self.patterns.clear();
        self
    }

    pub fn get_patterns(&self) -> &[Pattern] {
        &self.patterns
    }

    pub fn fragment_pattern(
        &mut self,
        name: &str,
        parts: usize,
        destructive: bool,
    ) -> Result<Vec<String>, Error> {
        if parts < 2 {
            return Err(Error::Validation(
                "fragment_pattern requires at least 2 parts".to_string(),
            ));
        }

        let source = self
            .patterns
            .iter()
            .find(|pattern| pattern.name == name.trim())
            .cloned()
            .ok_or_else(|| Error::Validation(format!("pattern not found: {}", name.trim())))?;

        if source.kind != PatternKind::Hex {
            return Err(Error::Validation(
                "fragment_pattern only supports hex patterns".to_string(),
            ));
        }

        let tokens = tokenize_hex_pattern(&source.value)?;
        if tokens.len() < parts {
            return Err(Error::Validation(format!(
                "cannot fragment {} hex tokens into {} parts",
                tokens.len(),
                parts
            )));
        }

        let base = tokens.len() / parts;
        let remainder = tokens.len() % parts;
        let mut start = 0usize;
        let mut names = Vec::with_capacity(parts);

        for index in 0..parts {
            let len = base + usize::from(index < remainder);
            let end = start + len;
            let fragment_name = format!("{}_fragment_{}", source.name, index);
            let fragment_value = tokens[start..end].join(" ");
            self.patterns.push(Pattern {
                name: fragment_name.clone(),
                value: fragment_value,
                comment: source.comment.clone(),
                kind: PatternKind::Hex,
                ascii: false,
                wide: false,
                nocase: false,
                xor: false,
                base64: false,
                base64wide: false,
                fullword: false,
                private: false,
            });
            names.push(fragment_name);
            start = end;
        }

        if destructive {
            self.remove_pattern(&source.name);
        }

        Ok(names)
    }

    pub fn condition<T>(&self, value: T) -> Condition
    where
        T: Into<Condition>,
    {
        value.into()
    }

    pub fn condition_at_least<S>(&self, minimum: usize, patterns: Vec<S>) -> Condition
    where
        S: AsRef<str>,
    {
        let patterns = patterns
            .iter()
            .map(|pattern| pattern.as_ref().trim())
            .filter(|pattern| !pattern.is_empty())
            .collect::<Vec<_>>();
        Condition::Raw(format!("{} of ({})", minimum, patterns.join(", ")))
    }

    pub fn condition_and(&self, parts: Vec<Condition>) -> Condition {
        Condition::And(parts)
    }

    pub fn condition_or(&self, parts: Vec<Condition>) -> Condition {
        Condition::Or(parts)
    }

    pub fn condition_not(&self, part: Condition) -> Condition {
        Condition::Not(Box::new(part))
    }

    pub fn set_condition<T>(&mut self, value: T) -> &mut Self
    where
        T: Into<Condition>,
    {
        self.condition = Some(value.into());
        self
    }

    pub fn add_condition<T>(&mut self, value: T) -> &mut Self
    where
        T: Into<Condition>,
    {
        let value = value.into();
        if value.render().trim().is_empty() {
            return self;
        }

        self.condition = match self.condition.take() {
            Some(existing) if !existing.render().trim().is_empty() => {
                Some(Condition::And(vec![existing, value]))
            }
            _ => Some(value),
        };
        self
    }

    pub fn clear_condition(&mut self) -> &mut Self {
        self.condition = None;
        self
    }

    pub fn get_condition(&self) -> Option<&Condition> {
        self.condition.as_ref()
    }

    pub fn get_condition_text(&self) -> Option<String> {
        self.condition.as_ref().map(Condition::render)
    }

    pub fn render(&self) -> String {
        let mut output = String::new();
        for import in &self.imports {
            output.push_str(&format!("import \"{}\"\n", escape_yara_string(import)));
        }
        if !self.imports.is_empty() {
            output.push('\n');
        }
        if let Some(comment) = &self.comment {
            output.push_str(&format!("// {}\n", comment));
        }
        if self.global {
            output.push_str("global ");
        }
        if self.private {
            output.push_str("private ");
        }
        output.push_str(&format!("rule {}", self.name));
        if !self.tags.is_empty() {
            output.push_str(&format!(" : {}", self.tags.join(" ")));
        }
        output.push_str(" {\n");

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
            self.condition
                .as_ref()
                .map(Condition::render)
                .unwrap_or_else(|| "all of them".to_string())
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
        self.remove(rule.get_name());
        self.rules.push(rule);
        self
    }

    pub fn remove(&mut self, name: &str) -> bool {
        let before = self.rules.len();
        self.rules.retain(|rule| rule.get_name() != name.trim());
        self.rules.len() != before
    }

    pub fn clear(&mut self) -> &mut Self {
        self.rules.clear();
        self
    }

    pub fn get_rules(&self) -> &[Rule] {
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

impl Match {
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
    pub fn get_matches(&self) -> &[Match] {
        &self.matches
    }
}

impl IntoIterator for ScanResults {
    type Item = Match;
    type IntoIter = std::vec::IntoIter<Match>;

    fn into_iter(self) -> Self::IntoIter {
        self.matches.into_iter()
    }
}

impl<'a> IntoIterator for &'a ScanResults {
    type Item = &'a Match;
    type IntoIter = std::slice::Iter<'a, Match>;

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

fn render_condition_group(operator: &str, parts: &[Condition]) -> String {
    let parts = parts
        .iter()
        .map(|part| format!("({})", part.render()))
        .collect::<Vec<_>>();
    parts.join(&format!(" {} ", operator))
}

fn tokenize_hex_pattern(value: &str) -> Result<Vec<String>, Error> {
    let normalized = value
        .trim()
        .trim_start_matches('{')
        .trim_end_matches('}')
        .trim();

    if normalized.is_empty() {
        return Err(Error::Validation(
            "hex pattern must not be empty".to_string(),
        ));
    }

    if normalized.chars().any(char::is_whitespace) {
        let tokens = normalized
            .split_whitespace()
            .map(str::trim)
            .filter(|token| !token.is_empty())
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        if tokens.is_empty() {
            return Err(Error::Validation(
                "hex pattern must not be empty".to_string(),
            ));
        }
        for token in &tokens {
            validate_fragment_token(token)?;
        }
        return Ok(tokens);
    }

    if normalized.len() % 2 != 0 {
        return Err(Error::Validation(
            "compact hex pattern must have an even number of characters".to_string(),
        ));
    }

    let tokens = normalized
        .as_bytes()
        .chunks(2)
        .map(|chunk| std::str::from_utf8(chunk).unwrap().to_string())
        .collect::<Vec<_>>();
    for token in &tokens {
        validate_fragment_token(token)?;
    }
    Ok(tokens)
}

fn validate_fragment_token(token: &str) -> Result<(), Error> {
    if token.len() != 2 {
        return Err(Error::Validation(format!(
            "fragment_pattern only supports hex byte pairs and wildcard pairs, got: {}",
            token
        )));
    }
    if token.chars().all(|c| c == '?' || c.is_ascii_hexdigit()) {
        return Ok(());
    }
    Err(Error::Validation(format!(
        "fragment_pattern only supports hex byte pairs and wildcard pairs, got: {}",
        token
    )))
}

fn validate_text_modifiers(
    nocase: bool,
    xor: bool,
    base64: bool,
    base64wide: bool,
    fullword: bool,
) -> Result<(), Error> {
    if nocase && xor {
        return Err(Error::Validation(
            "nocase cannot be used with xor".to_string(),
        ));
    }
    if nocase && base64 {
        return Err(Error::Validation(
            "nocase cannot be used with base64".to_string(),
        ));
    }
    if nocase && base64wide {
        return Err(Error::Validation(
            "nocase cannot be used with base64wide".to_string(),
        ));
    }
    if xor && base64 {
        return Err(Error::Validation(
            "xor cannot be used with base64".to_string(),
        ));
    }
    if xor && base64wide {
        return Err(Error::Validation(
            "xor cannot be used with base64wide".to_string(),
        ));
    }
    if base64 && fullword {
        return Err(Error::Validation(
            "base64 cannot be used with fullword".to_string(),
        ));
    }
    if base64wide && fullword {
        return Err(Error::Validation(
            "base64wide cannot be used with fullword".to_string(),
        ));
    }
    if base64 && base64wide {
        return Err(Error::Validation(
            "base64 cannot be used with base64wide".to_string(),
        ));
    }
    Ok(())
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
            if pattern.nocase {
                rendered.push_str(" nocase");
            }
            if pattern.xor {
                rendered.push_str(" xor");
            }
            if pattern.base64 {
                rendered.push_str(" base64");
            }
            if pattern.base64wide {
                rendered.push_str(" base64wide");
            }
            if pattern.fullword {
                rendered.push_str(" fullword");
            }
            if pattern.private {
                rendered.push_str(" private");
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
                matches.push(Match {
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
    use super::{Condition, Rule, RuleSet};

    #[test]
    fn rule_defaults_name_and_all_of_them_condition() {
        let mut rule = Rule::new();
        rule.set_metadata("author", "analyst");
        rule.add_pattern("55 8B EC ??", Some("prologue"));
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
        rule.add_pattern("AA BB CC", None);
        rule.add_pattern("DD EE FF", None);
        rule.set_condition("2 of them");
        let text = rule.render();
        assert!(text.contains("rule dispatcher_like"));
        assert!(text.contains("condition:\n    2 of them"));
    }

    #[test]
    fn rule_supports_metadata_replacement_and_removal() {
        let mut rule = Rule::new_with_options(Some("meta_test"), None);
        rule.set_metadata("author", "analyst");
        rule.set_metadata("author", "researcher");
        rule.set_metadata("score", 10);
        assert_eq!(rule.get_metadata().len(), 2);
        assert!(rule.remove_metadata("score"));
        assert_eq!(rule.get_metadata().len(), 1);
        assert_eq!(rule.get_metadata()[0].0, "author");
    }

    #[test]
    fn rule_supports_named_pattern_mutation() {
        let mut rule = Rule::new_with_options(Some("pattern_test"), None);
        let first = rule.add_pattern("AA BB", Some("first"));
        let second = rule.add_pattern("CC DD", None);
        assert_eq!(first, "$chromosome_0");
        assert_eq!(second, "$chromosome_1");
        assert!(rule.update_pattern(&second, Some("EE FF"), Some(Some("updated"))));
        assert!(rule.remove_pattern(&first));
        let text = rule.render();
        assert!(!text.contains("$chromosome_0 ="));
        assert!(text.contains("$chromosome_1 = { EE FF }"));
        assert!(text.contains("// updated"));
    }

    #[test]
    fn rule_supports_condition_clear() {
        let mut rule = Rule::new_with_options(Some("condition_test"), None);
        rule.set_condition("1 of them");
        assert_eq!(rule.get_condition_text().as_deref(), Some("1 of them"));
        rule.clear_condition();
        assert_eq!(rule.get_condition(), None);
        assert!(rule.render().contains("condition:\n    all of them"));
    }

    #[test]
    fn rule_supports_add_condition_composition() {
        let mut rule = Rule::new_with_options(Some("condition_append"), None);
        rule.add_condition("1 of them");
        rule.add_condition("filesize < 5MB");
        assert_eq!(
            rule.get_condition_text().as_deref(),
            Some("(1 of them) and (filesize < 5MB)")
        );
    }

    #[test]
    fn rule_supports_nested_condition_builders() {
        let mut rule = Rule::new_with_options(Some("nested"), None);
        let a = rule.add_pattern("AA BB", None);
        let b = rule.add_pattern("CC DD", None);
        let c = rule.add_pattern("EE FF", None);
        let condition = rule.condition_and(vec![
            rule.condition_or(vec![rule.condition(a.as_str()), rule.condition(b.as_str())]),
            rule.condition_not(rule.condition(c.as_str())),
            rule.condition("filesize < 1MB"),
        ]);
        rule.set_condition(condition);
        assert_eq!(
            rule.get_condition(),
            Some(&Condition::And(vec![
                Condition::Or(vec![Condition::Raw(a.clone()), Condition::Raw(b.clone())]),
                Condition::Not(Box::new(Condition::Raw(c.clone()))),
                Condition::Raw("filesize < 1MB".to_string())
            ]))
        );
        assert_eq!(
            rule.get_condition_text().as_deref(),
            Some(
                "(($chromosome_0) or ($chromosome_1)) and (not ($chromosome_2)) and (filesize < 1MB)"
            )
        );
    }

    #[test]
    fn rule_can_fragment_hex_patterns() {
        let mut rule = Rule::new_with_options(Some("fragmented"), None);
        let pattern = rule.add_pattern("48 8B 05 11 22 33 44 48 85 C0", Some("anchor"));
        let fragments = rule.fragment_pattern(&pattern, 3, true).unwrap();
        assert_eq!(
            fragments,
            vec![
                "$chromosome_0_fragment_0".to_string(),
                "$chromosome_0_fragment_1".to_string(),
                "$chromosome_0_fragment_2".to_string()
            ]
        );
        let rendered = rule.render();
        assert!(!rendered.contains("$chromosome_0 = { 48 8B 05 11 22 33 44 48 85 C0 }"));
        assert!(rendered.contains("$chromosome_0_fragment_0 = { 48 8B 05 11 }"));
        assert!(rendered.contains("$chromosome_0_fragment_1 = { 22 33 44 }"));
        assert!(rendered.contains("$chromosome_0_fragment_2 = { 48 85 C0 }"));
    }

    #[test]
    fn rule_can_fragment_compact_hex_patterns() {
        let mut rule = Rule::new_with_options(Some("fragmented_compact"), None);
        let pattern = rule.add_pattern("488B05112233444885C0", None);
        let fragments = rule.fragment_pattern(&pattern, 3, true).unwrap();
        assert_eq!(
            fragments,
            vec![
                "$chromosome_0_fragment_0".to_string(),
                "$chromosome_0_fragment_1".to_string(),
                "$chromosome_0_fragment_2".to_string()
            ]
        );
        let rendered = rule.render();
        assert!(!rendered.contains("$chromosome_0 = { 488B05112233444885C0 }"));
        assert!(rendered.contains("$chromosome_0_fragment_0 = { 48 8B 05 11 }"));
        assert!(rendered.contains("$chromosome_0_fragment_1 = { 22 33 44 }"));
        assert!(rendered.contains("$chromosome_0_fragment_2 = { 48 85 C0 }"));
    }

    #[test]
    fn rule_can_fragment_patterns_non_destructively() {
        let mut rule = Rule::new_with_options(Some("fragmented_keep"), None);
        let pattern = rule.add_pattern("48 8B 05 11 22 33 44 48 85 C0", None);
        let _ = rule.fragment_pattern(&pattern, 3, false).unwrap();
        let rendered = rule.render();
        assert!(rendered.contains("$chromosome_0 = { 48 8B 05 11 22 33 44 48 85 C0 }"));
        assert!(rendered.contains("$chromosome_0_fragment_0 = { 48 8B 05 11 }"));
    }

    #[test]
    fn rule_supports_condition_at_least() {
        let mut rule = Rule::new_with_options(Some("at_least"), None);
        let pattern = rule.add_pattern("48 8B 05 11 22 33 44 48 85 C0", None);
        let fragments = rule.fragment_pattern(&pattern, 3, true).unwrap();
        rule.set_condition(rule.condition_at_least(2, fragments.clone()));
        assert_eq!(
            rule.get_condition_text().as_deref(),
            Some(
                "2 of ($chromosome_0_fragment_0, $chromosome_0_fragment_1, $chromosome_0_fragment_2)"
            )
        );
    }

    #[test]
    fn rule_rejects_fragmenting_non_hex_patterns() {
        let mut rule = Rule::new_with_options(Some("invalid_fragment"), None);
        let text = rule
            .add_text(
                "powershell",
                true,
                false,
                false,
                false,
                false,
                false,
                false,
                false,
                None,
            )
            .unwrap();
        let error = rule.fragment_pattern(&text, 2, true).unwrap_err();
        assert_eq!(
            error.to_string(),
            "fragment_pattern only supports hex patterns"
        );
    }

    #[test]
    fn rule_rejects_fragmenting_advanced_yara_hex_syntax() {
        let mut rule = Rule::new_with_options(Some("invalid_yara_hex"), None);
        let pattern = rule.add_pattern("de ad [1-2] be ef", None);
        let error = rule.fragment_pattern(&pattern, 2, true).unwrap_err();
        assert_eq!(
            error.to_string(),
            "fragment_pattern only supports hex byte pairs and wildcard pairs, got: [1-2]"
        );
    }

    #[test]
    fn rule_supports_imports() {
        let mut rule = Rule::new_with_options(Some("imports_test"), Some("module-backed"));
        rule.add_import("pe");
        rule.add_import("math");
        rule.add_import("pe");
        rule.add_pattern("AA BB", None);
        let rendered = rule.render();
        assert!(rendered.starts_with(
            "import \"pe\"\nimport \"math\"\n\n// module-backed\nrule imports_test {"
        ));
    }

    #[test]
    fn rule_supports_import_and_tag_removal() {
        let mut rule = Rule::new_with_options(Some("cleanup_test"), None);
        rule.add_import("pe");
        rule.add_import("math");
        rule.add_tag("Foo");
        rule.add_tag("Bar");
        assert!(rule.remove_import("math"));
        assert!(rule.remove_tag("Bar"));
        rule.clear_imports();
        rule.clear_tags();
        rule.add_pattern("AA BB", None);
        let rendered = rule.render();
        assert!(!rendered.contains("import \"pe\""));
        assert!(!rendered.contains("import \"math\""));
        assert!(rendered.starts_with("rule cleanup_test {\n"));
    }

    #[test]
    fn rule_supports_tags() {
        let mut rule = Rule::new_with_options(Some("tags_test"), None);
        rule.add_tag("Foo");
        rule.add_tag("Bar");
        rule.add_tag("Foo");
        rule.add_pattern("AA BB", None);
        let rendered = rule.render();
        assert!(rendered.starts_with("rule tags_test : Foo Bar {\n"));
    }

    #[test]
    fn rule_supports_global_and_private_flags() {
        let mut rule = Rule::new_with_options(Some("scoped_test"), None);
        rule.set_global(true);
        rule.set_private(true);
        rule.add_tag("Foo");
        rule.add_pattern("AA BB", None);
        assert!(rule.is_global());
        assert!(rule.is_private());
        let rendered = rule.render();
        assert!(rendered.starts_with("global private rule scoped_test : Foo {\n"));
    }

    #[test]
    fn rule_can_check_and_scan() {
        let mut rule = Rule::new_with_options(Some("scan_test"), None);
        rule.add_pattern("61 62 63", Some("abc"));
        rule.set_condition("all of them");
        assert!(rule.check());
        let results = rule.scan(b"abc").unwrap();
        assert_eq!(results.get_matches().len(), 1);
        assert_eq!(results.get_matches()[0].rule(), "scan_test");
        assert_eq!(results.get_matches()[0].offset(), 0);
        assert_eq!(results.get_matches()[0].data(), b"abc");
        assert_eq!(results.get_matches()[0].size(), 3);
    }

    #[test]
    fn rule_supports_text_regex_and_named_conditions() {
        let mut rule = Rule::new_with_options(Some("hybrid"), None);
        let chromosome = rule.add_pattern("61 62 63", Some("hex"));
        let text = rule
            .add_text(
                "powershell",
                true,
                true,
                false,
                false,
                false,
                false,
                false,
                false,
                Some("text"),
            )
            .unwrap();
        let regex = rule.add_regex(r"https?://example\.com", Some("regex"));
        let custom = rule.add_string("xor wide ascii \"cmd.exe\"", Some("custom"));
        rule.set_condition(&format!(
            "2 of ({}, {}, {}, {})",
            chromosome, text, regex, custom
        ));
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
        rule.add_pattern("AA BB", None);
        let rendered = rule.render();
        assert!(rendered.starts_with("// generated from binlex\nrule commented {"));
    }

    #[test]
    fn rule_supports_text_modifiers() {
        let mut rule = Rule::new_with_options(Some("modifiers"), None);
        rule.add_text(
            "powershell",
            true,
            true,
            false,
            false,
            false,
            false,
            true,
            true,
            None,
        )
        .unwrap();
        let rendered = rule.render();
        assert!(rendered.contains("$text_0 = \"powershell\" ascii wide fullword private"));
    }

    #[test]
    fn rule_rejects_invalid_text_modifier_combinations() {
        let mut rule = Rule::new_with_options(Some("invalid_modifiers"), None);
        let error = rule
            .add_text(
                "powershell",
                true,
                false,
                true,
                true,
                false,
                false,
                false,
                false,
                None,
            )
            .unwrap_err();
        assert_eq!(error.to_string(), "nocase cannot be used with xor");
    }

    #[test]
    fn ruleset_can_scan_multiple_rules() {
        let mut first = Rule::new_with_options(Some("first"), None);
        first.add_pattern("61 62 63", None);
        first.set_condition("all of them");

        let mut second = Rule::new_with_options(Some("second"), None);
        second.add_pattern("64 65 66", None);
        second.set_condition("all of them");

        let mut rules = RuleSet::new();
        rules.add(first);
        rules.add(second);

        assert!(rules.check());
        let results = rules.scan(b"abcdef").unwrap();
        let names = results
            .get_matches()
            .iter()
            .map(|matched| matched.rule().to_string())
            .collect::<Vec<_>>();
        assert!(names.contains(&"first".to_string()));
        assert!(names.contains(&"second".to_string()));
    }
}
