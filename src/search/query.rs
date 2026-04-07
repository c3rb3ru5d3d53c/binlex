use crate::Architecture;
use crate::indexing::Collection;
use chrono::{DateTime, Duration, Months, NaiveDate, TimeZone, Utc};
use serde::Serialize;
use std::fmt;
use winnow::Parser;
use winnow::ascii::{Caseless, multispace0};
use winnow::error::ContextError;
use winnow::token::take_while;

#[derive(Clone, Debug, Serialize)]
pub struct Query {
    raw: String,
    expr: QueryExpr,
}

impl Query {
    pub fn parse(input: impl AsRef<str>) -> Result<Self, QueryError> {
        let raw = input.as_ref().to_string();
        let tokens = tokenize_search_query(&raw)?;
        let expr = parse_search_query(&tokens)?;
        Ok(Self { raw, expr })
    }

    pub fn raw(&self) -> &str {
        &self.raw
    }

    pub fn expr(&self) -> &QueryExpr {
        &self.expr
    }

    pub fn analyze(&self) -> Result<QueryAnalysis, QueryError> {
        let mut analysis = QueryAnalysis::default();
        analyze_query_expr(&self.expr, &mut analysis, false, false)?;
        Ok(analysis)
    }
}

pub fn query_architecture_values() -> Vec<String> {
    Architecture::all()
        .iter()
        .map(ToString::to_string)
        .collect()
}

pub fn query_collection_values() -> Vec<String> {
    Collection::all()
        .iter()
        .map(|collection| collection.as_str().to_string())
        .collect()
}

#[derive(Clone, Debug, Serialize)]
pub struct QueryCompletionSpec {
    pub label: &'static str,
    pub insert: &'static str,
    pub kind: &'static str,
    pub usage: &'static str,
    pub description: &'static str,
}

pub fn query_completion_specs() -> Vec<QueryCompletionSpec> {
    vec![
        QueryCompletionSpec {
            label: "sample:",
            insert: "sample:",
            kind: "field",
            usage: "sample:<64-hex-hash>",
            description: "Root a search from a specific sample",
        },
        QueryCompletionSpec {
            label: "embedding:",
            insert: "embedding:",
            kind: "field",
            usage: "embedding:<64-hex-hash>",
            description: "Nearest-neighbor search from an existing embedding",
        },
        QueryCompletionSpec {
            label: "embeddings:",
            insert: "embeddings:",
            kind: "field",
            usage: "embeddings:>1k",
            description: "Filter by embedding count with comparisons",
        },
        QueryCompletionSpec {
            label: "vector:",
            insert: "vector:",
            kind: "field",
            usage: "vector:[0.1, -0.2, 0.3]",
            description: "Nearest-neighbor search from an explicit vector",
        },
        QueryCompletionSpec {
            label: "score:",
            insert: "score:",
            kind: "field",
            usage: "score:>0.95",
            description: "Filter by similarity score with comparisons",
        },
        QueryCompletionSpec {
            label: "expand:",
            insert: "expand:",
            kind: "field",
            usage: "expand:blocks",
            description: "Expand rows downward to child blocks or instructions",
        },
        QueryCompletionSpec {
            label: "corpus:",
            insert: "corpus:",
            kind: "field",
            usage: "corpus:<name>",
            description: "Filter by corpus name",
        },
        QueryCompletionSpec {
            label: "collection:",
            insert: "collection:",
            kind: "field",
            usage: "collection:functions",
            description: "Filter by indexed entity type",
        },
        QueryCompletionSpec {
            label: "architecture:",
            insert: "architecture:",
            kind: "field",
            usage: "architecture:amd64",
            description: "Filter by architecture",
        },
        QueryCompletionSpec {
            label: "username:",
            insert: "username:",
            kind: "field",
            usage: "username:anonymous",
            description: "Filter by the indexing username",
        },
        QueryCompletionSpec {
            label: "address:",
            insert: "address:",
            kind: "field",
            usage: "address:0x401000",
            description: "Filter by exact address",
        },
        QueryCompletionSpec {
            label: "timestamp:",
            insert: "timestamp:",
            kind: "field",
            usage: "timestamp:>=2026-03-01",
            description: "Filter by indexed UTC timestamp or date range bounds",
        },
        QueryCompletionSpec {
            label: "size:",
            insert: "size:",
            kind: "field",
            usage: "size:>1mb",
            description: "Filter by instruction, block, or function byte size",
        },
        QueryCompletionSpec {
            label: "symbol:",
            insert: "symbol:",
            kind: "field",
            usage: "symbol:\"kernel32:CreateFileW\"",
            description: "Filter by quoted fuzzy symbol name matches",
        },
        QueryCompletionSpec {
            label: "tag:",
            insert: "tag:",
            kind: "field",
            usage: "tag:malware:emotet",
            description: "Filter by exact entity tag name",
        },
        QueryCompletionSpec {
            label: "symbols:",
            insert: "symbols:",
            kind: "field",
            usage: "symbols:>0",
            description: "Filter by the number of entity symbols",
        },
        QueryCompletionSpec {
            label: "tags:",
            insert: "tags:",
            kind: "field",
            usage: "tags:>0",
            description: "Filter by the number of entity tags",
        },
        QueryCompletionSpec {
            label: "comments:",
            insert: "comments:",
            kind: "field",
            usage: "comments:>0",
            description: "Filter by the number of entity comments",
        },
        QueryCompletionSpec {
            label: "cyclomatic_complexity:",
            insert: "cyclomatic_complexity:",
            kind: "field",
            usage: "cyclomatic_complexity:>5",
            description: "Filter by cyclomatic complexity",
        },
        QueryCompletionSpec {
            label: "average_instructions_per_block:",
            insert: "average_instructions_per_block:",
            kind: "field",
            usage: "average_instructions_per_block:<10",
            description: "Filter by average instructions per block",
        },
        QueryCompletionSpec {
            label: "instructions:",
            insert: "instructions:",
            kind: "field",
            usage: "instructions:>=32",
            description: "Filter by the number of instructions",
        },
        QueryCompletionSpec {
            label: "blocks:",
            insert: "blocks:",
            kind: "field",
            usage: "blocks:>=4",
            description: "Filter by the number of blocks",
        },
        QueryCompletionSpec {
            label: "markov:",
            insert: "markov:",
            kind: "field",
            usage: "markov:>0.6",
            description: "Filter by block Markov score",
        },
        QueryCompletionSpec {
            label: "entropy:",
            insert: "entropy:",
            kind: "field",
            usage: "entropy:<6.5",
            description: "Filter by byte entropy",
        },
        QueryCompletionSpec {
            label: "contiguous:",
            insert: "contiguous:",
            kind: "field",
            usage: "contiguous:true",
            description: "Filter by contiguous layout",
        },
        QueryCompletionSpec {
            label: "chromosome.entropy:",
            insert: "chromosome.entropy:",
            kind: "field",
            usage: "chromosome.entropy:>3.0",
            description: "Filter by chromosome entropy",
        },
        QueryCompletionSpec {
            label: "limit:",
            insert: "limit:",
            kind: "field",
            usage: "limit:10",
            description: "Cap the current result stream",
        },
        QueryCompletionSpec {
            label: "drop:",
            insert: "drop:",
            kind: "field",
            usage: "drop:rhs",
            description: "Project compare results onto one side",
        },
        QueryCompletionSpec {
            label: "|",
            insert: " | ",
            kind: "operator",
            usage: "term | term",
            description: "Pipe results through another narrowing filter",
        },
        QueryCompletionSpec {
            label: "||",
            insert: " || ",
            kind: "operator",
            usage: "term || term",
            description: "Match either clause",
        },
        QueryCompletionSpec {
            label: "!",
            insert: "!",
            kind: "operator",
            usage: "!term",
            description: "Negate the next term or group",
        },
        QueryCompletionSpec {
            label: "->",
            insert: " -> ",
            kind: "operator",
            usage: "left-query -> right-query",
            description: "Compare each left-side result to its best right-side match",
        },
        QueryCompletionSpec {
            label: "<-",
            insert: " <- ",
            kind: "operator",
            usage: "left-query <- right-query",
            description: "Compare each right-side result to its best left-side match",
        },
        QueryCompletionSpec {
            label: "ascending:",
            insert: "ascending:",
            kind: "field",
            usage: "ascending:score",
            description: "Sort the current result stream in ascending order by a specific field",
        },
        QueryCompletionSpec {
            label: "descending:",
            insert: "descending:",
            kind: "field",
            usage: "descending:score",
            description: "Sort the current result stream in descending order by a specific field",
        },
        QueryCompletionSpec {
            label: "(",
            insert: "(",
            kind: "group",
            usage: "( term )",
            description: "Start a grouped sub-expression",
        },
        QueryCompletionSpec {
            label: ")",
            insert: ")",
            kind: "group",
            usage: "( term )",
            description: "Close the current grouped sub-expression",
        },
    ]
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum QueryField {
    Sha256,
    Embedding,
    Embeddings,
    Vector,
    Score,
    Corpus,
    Collection,
    Architecture,
    Username,
    Address,
    Timestamp,
    Size,
    Symbol,
    Tag,
    Symbols,
    Tags,
    Comments,
    CyclomaticComplexity,
    AverageInstructionsPerBlock,
    NumberOfInstructions,
    NumberOfBlocks,
    Markov,
    Entropy,
    Contiguous,
    ChromosomeEntropy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum QueryCollection {
    Instruction,
    Block,
    Function,
}

impl QueryCollection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Instruction => "instructions",
            Self::Block => "blocks",
            Self::Function => "functions",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "instructions" => Some(Self::Instruction),
            "blocks" => Some(Self::Block),
            "functions" => Some(Self::Function),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct QueryTerm {
    pub field: QueryField,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum QueryExpr {
    Term(QueryTerm),
    Not(Box<QueryExpr>),
    And(Box<QueryExpr>, Box<QueryExpr>),
    Or(Box<QueryExpr>, Box<QueryExpr>),
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub enum SearchRoot {
    Sha256(String),
    Embedding(String),
    Vector(Vec<f32>),
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct QueryAnalysis {
    pub root: Option<SearchRoot>,
    pub corpora: Vec<String>,
    pub collections: Vec<QueryCollection>,
    pub architectures: Vec<Architecture>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum QueryToken {
    Term(QueryTerm),
    And,
    Or,
    Not,
    LParen,
    RParen,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QueryError(pub String);

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for QueryError {}

fn analyze_query_expr(
    expr: &QueryExpr,
    analysis: &mut QueryAnalysis,
    negated: bool,
    inside_or: bool,
) -> Result<(), QueryError> {
    match expr {
        QueryExpr::Term(term) => analyze_query_term(term, analysis, negated, inside_or),
        QueryExpr::Not(inner) => analyze_query_expr(inner, analysis, true, inside_or),
        QueryExpr::And(lhs, rhs) => {
            analyze_query_expr(lhs, analysis, negated, inside_or)?;
            analyze_query_expr(rhs, analysis, negated, inside_or)
        }
        QueryExpr::Or(lhs, rhs) => {
            analyze_query_expr(lhs, analysis, negated, true)?;
            analyze_query_expr(rhs, analysis, negated, true)
        }
    }
}

fn analyze_query_term(
    term: &QueryTerm,
    analysis: &mut QueryAnalysis,
    negated: bool,
    inside_or: bool,
) -> Result<(), QueryError> {
    match term.field {
        QueryField::Embedding => {
            if negated || inside_or {
                return Err(QueryError(
                    "embedding queries can only be combined with `|` filters".to_string(),
                ));
            }
            if !is_sha256(term.value.trim()) {
                return Err(QueryError(
                    "embedding must be 64 hexadecimal characters".to_string(),
                ));
            }
            set_search_root(
                analysis,
                SearchRoot::Embedding(term.value.trim().to_ascii_lowercase()),
            )
        }
        QueryField::Sha256 => {
            if inside_or && !negated {
                return Err(QueryError(
                    "sha256 queries can only be combined with `|` filters".to_string(),
                ));
            }
            if !is_sha256(term.value.trim()) {
                return Err(QueryError(
                    "sha256 must be 64 hexadecimal characters".to_string(),
                ));
            }
            if negated {
                return Ok(());
            }
            set_search_root(
                analysis,
                SearchRoot::Sha256(term.value.trim().to_ascii_lowercase()),
            )
        }
        QueryField::Vector => {
            if negated || inside_or {
                return Err(QueryError(
                    "vector queries can only be combined with `|` filters".to_string(),
                ));
            }
            let vector = parse_query_vector(term.value.trim()).ok_or_else(|| {
                QueryError("vector expects a JSON array with at least two numbers".to_string())
            })?;
            set_search_root(analysis, SearchRoot::Vector(vector))
        }
        QueryField::Embeddings => {
            if parse_positive_count_query(term.value.trim()).is_none() {
                return Err(QueryError(
                    "embeddings expects counts with optional comparisons like embeddings:>1k or embeddings:<=12m"
                        .to_string(),
                ));
            }
            Ok(())
        }
        QueryField::Score => {
            if parse_score_query(term.value.trim()).is_none() {
                return Err(QueryError(
                    "score expects decimal comparisons like score:>0.95 or score:<=1.0".to_string(),
                ));
            }
            Ok(())
        }
        QueryField::Corpus if !negated => push_unique_string(&mut analysis.corpora, &term.value),
        QueryField::Collection if !negated => {
            let collection = QueryCollection::parse(&term.value)
                .ok_or_else(|| QueryError(format!("invalid collection {}", term.value)))?;
            push_unique_collection(&mut analysis.collections, collection);
            Ok(())
        }
        QueryField::Architecture if !negated => {
            let architecture = Architecture::from_string(&term.value)
                .map_err(|_| QueryError(format!("invalid architecture {}", term.value)))?;
            push_unique_architecture(&mut analysis.architectures, architecture);
            Ok(())
        }
        QueryField::Username => {
            if term.value.trim().is_empty() {
                return Err(QueryError("username requires a value".to_string()));
            }
            Ok(())
        }
        QueryField::Address => {
            if parse_query_address(term.value.trim()).is_none() {
                return Err(QueryError(format!("invalid address {}", term.value)));
            }
            Ok(())
        }
        QueryField::Timestamp => {
            if parse_date_query(term.value.trim()).is_none() {
                return Err(QueryError(
                    "timestamp expects YYYY, YYYY-MM, YYYY-MM-DD, or comparisons like timestamp:>=2026-03-01"
                        .to_string(),
                ));
            }
            Ok(())
        }
        QueryField::Size => {
            if parse_size_query(term.value.trim()).is_none() {
                return Err(QueryError(
                    "size expects bytes with optional comparisons like size:>64 or size:>=1mb"
                        .to_string(),
                ));
            }
            Ok(())
        }
        QueryField::Tag => {
            if term.value.trim().is_empty() {
                return Err(QueryError("tag requires a value".to_string()));
            }
            Ok(())
        }
        QueryField::Symbols
        | QueryField::Tags
        | QueryField::Comments
        | QueryField::CyclomaticComplexity
        | QueryField::NumberOfInstructions
        | QueryField::NumberOfBlocks => {
            if parse_integer_query(term.value.trim()).is_none() {
                return Err(QueryError(format!(
                    "{} expects integer comparisons like {}:>5",
                    match term.field {
                        QueryField::Symbols => "symbols",
                        QueryField::Tags => "tags",
                        QueryField::Comments => "comments",
                        QueryField::CyclomaticComplexity => "cyclomatic_complexity",
                        QueryField::NumberOfInstructions => "instructions",
                        _ => "blocks",
                    },
                    match term.field {
                        QueryField::Symbols => "symbols",
                        QueryField::Tags => "tags",
                        QueryField::Comments => "comments",
                        QueryField::CyclomaticComplexity => "cyclomatic_complexity",
                        QueryField::NumberOfInstructions => "instructions",
                        _ => "blocks",
                    }
                )));
            }
            Ok(())
        }
        QueryField::AverageInstructionsPerBlock
        | QueryField::Markov
        | QueryField::Entropy
        | QueryField::ChromosomeEntropy => {
            if parse_float_query(term.value.trim()).is_none() {
                return Err(QueryError(format!(
                    "{} expects decimal comparisons like {}:>1.5",
                    match term.field {
                        QueryField::AverageInstructionsPerBlock => "average_instructions_per_block",
                        QueryField::Markov => "markov",
                        QueryField::Entropy => "entropy",
                        _ => "chromosome.entropy",
                    },
                    match term.field {
                        QueryField::AverageInstructionsPerBlock => "average_instructions_per_block",
                        QueryField::Markov => "markov",
                        QueryField::Entropy => "entropy",
                        _ => "chromosome.entropy",
                    }
                )));
            }
            Ok(())
        }
        QueryField::Contiguous => {
            if parse_bool_query(term.value.trim()).is_none() {
                return Err(QueryError("contiguous expects true or false".to_string()));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn set_search_root(analysis: &mut QueryAnalysis, root: SearchRoot) -> Result<(), QueryError> {
    match (&analysis.root, &root) {
        (None, _) => {
            analysis.root = Some(root);
            Ok(())
        }
        (Some(SearchRoot::Embedding(lhs)), SearchRoot::Embedding(rhs)) if lhs == rhs => Ok(()),
        (Some(SearchRoot::Sha256(lhs)), SearchRoot::Sha256(rhs)) if lhs == rhs => Ok(()),
        (Some(SearchRoot::Vector(lhs)), SearchRoot::Vector(rhs))
            if lhs.len() == rhs.len()
                && lhs
                    .iter()
                    .zip(rhs.iter())
                    .all(|(left, right)| (*left - *right).abs() < f32::EPSILON) =>
        {
            Ok(())
        }
        _ => Err(QueryError(
            "only one primary search root is supported per query".to_string(),
        )),
    }
}

fn push_unique_string(values: &mut Vec<String>, value: &str) -> Result<(), QueryError> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return Err(QueryError("query values must not be empty".to_string()));
    }
    if !values.iter().any(|existing| existing == normalized) {
        values.push(normalized.to_string());
    }
    Ok(())
}

fn push_unique_collection(values: &mut Vec<QueryCollection>, value: QueryCollection) {
    if !values.contains(&value) {
        values.push(value);
    }
}

fn push_unique_architecture(values: &mut Vec<Architecture>, value: Architecture) {
    if !values.contains(&value) {
        values.push(value);
    }
}

fn tokenize_search_query(query: &str) -> Result<Vec<QueryToken>, QueryError> {
    let mut input = query;
    let mut tokens = Vec::new();
    while !input.is_empty() {
        skip_query_whitespace(&mut input);
        if input.is_empty() {
            break;
        }
        if let Some(remainder) = input.strip_prefix('(') {
            input = remainder;
            tokens.push(QueryToken::LParen);
            continue;
        }
        if let Some(remainder) = input.strip_prefix(')') {
            input = remainder;
            tokens.push(QueryToken::RParen);
            continue;
        }
        if let Some(operator) = parse_query_operator(&mut input) {
            tokens.push(operator);
            continue;
        }
        let head = parse_query_head(&mut input)?;
        skip_query_whitespace(&mut input);
        let colon_result: winnow::ModalResult<char, ContextError> = ':'.parse_next(&mut input);
        colon_result.map_err(|_| {
            QueryError(format!(
                "unexpected token {}. Use explicit fields like sample:, embedding:, embeddings:, or vector:",
                head
            ))
        })?;
        let field = parse_query_field(&head)?;
        skip_query_whitespace(&mut input);
        let value = match field {
            QueryField::Vector => parse_vector_token_value(&mut input)?,
            QueryField::Symbol => parse_quoted_query_value(&mut input)?,
            _ => parse_simple_query_value(&mut input)?,
        };
        if value.trim().is_empty() {
            return Err(QueryError(format!("{} requires a value", head)));
        }
        tokens.push(QueryToken::Term(QueryTerm { field, value }));
    }
    Ok(tokens)
}

fn parse_query_operator(input: &mut &str) -> Option<QueryToken> {
    if let Some(remainder) = input.strip_prefix("||") {
        *input = remainder;
        return Some(QueryToken::Or);
    }
    if let Some(remainder) = input.strip_prefix('|') {
        *input = remainder;
        return Some(QueryToken::And);
    }
    if let Some(remainder) = input.strip_prefix('!') {
        *input = remainder;
        return Some(QueryToken::Not);
    }
    for (label, token) in [
        ("AND", QueryToken::And),
        ("OR", QueryToken::Or),
        ("NOT", QueryToken::Not),
    ] {
        let checkpoint = *input;
        let keyword_result: winnow::ModalResult<&str, ContextError> =
            Caseless(label).parse_next(input);
        if keyword_result.is_ok() && is_query_boundary(input.chars().next()) {
            return Some(token);
        }
        *input = checkpoint;
    }
    None
}

fn parse_query_head(input: &mut &str) -> Result<String, QueryError> {
    let head_result: winnow::ModalResult<&str, ContextError> = take_while(1.., |ch: char| {
        !ch.is_whitespace()
            && ch != '('
            && ch != ')'
            && ch != ':'
            && ch != '|'
            && ch != '!'
            && ch != '~'
    })
    .parse_next(input);
    head_result
        .map(|head| head.to_string())
        .map_err(|_| QueryError("expected a search term".to_string()))
}

fn skip_query_whitespace(input: &mut &str) {
    let _: winnow::ModalResult<&str, ContextError> = multispace0.parse_next(input);
}

fn parse_simple_query_value(input: &mut &str) -> Result<String, QueryError> {
    let source = *input;
    let mut end = source.len();
    for (offset, ch) in source.char_indices() {
        if ch == '(' || ch == ')' || ch == '|' || ch == '~' {
            end = offset;
            break;
        }
        if ch.is_whitespace() {
            let remainder = &source[offset..];
            if next_query_operator_index(remainder).is_some() {
                end = offset;
                break;
            }
        }
    }
    *input = &source[end..];
    Ok(source[..end].trim().to_string())
}

fn next_query_operator_index(input: &str) -> Option<usize> {
    let mut remainder = input;
    let skipped = input.len() - input.trim_start_matches(char::is_whitespace).len();
    skip_query_whitespace(&mut remainder);
    let found = parse_query_operator(&mut remainder).is_some();
    if found { Some(skipped) } else { None }
}

fn parse_quoted_query_value(input: &mut &str) -> Result<String, QueryError> {
    if !input.starts_with('"') {
        return Err(QueryError(
            "symbol expects a quoted string like symbol:\"kernel32:CreateFileW\"".to_string(),
        ));
    }
    *input = &input[1..];
    let mut value = String::new();
    let mut escaped = false;
    let source = *input;
    let mut close_at = None;
    for (offset, ch) in source.char_indices() {
        if escaped {
            value.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '"' => {
                close_at = Some(offset);
                break;
            }
            _ => value.push(ch),
        }
    }
    if let Some(offset) = close_at {
        *input = &source[offset + 1..];
        return Ok(value);
    }
    Err(QueryError("symbol expects a closing quote".to_string()))
}

fn parse_vector_token_value(input: &mut &str) -> Result<String, QueryError> {
    skip_query_whitespace(input);
    if !input.starts_with('[') {
        return Err(QueryError("vector expects a JSON array".to_string()));
    }
    let source = *input;
    let mut depth = 0usize;
    for (offset, ch) in source.char_indices() {
        match ch {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth == 0 {
                    let end = offset + ch.len_utf8();
                    *input = &source[end..];
                    return Ok(source[..end].to_string());
                }
            }
            _ => {}
        }
    }
    Err(QueryError(
        "vector expects a balanced JSON array".to_string(),
    ))
}

fn is_query_boundary(next: Option<char>) -> bool {
    match next {
        None => true,
        Some(ch) => ch.is_whitespace() || ch == '(' || ch == ')' || ch == '|',
    }
}

fn parse_query_field(value: &str) -> Result<QueryField, QueryError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "sample" => Ok(QueryField::Sha256),
        "lhs" => Ok(QueryField::Sha256),
        "rhs" => Ok(QueryField::Sha256),
        "sha256" => Ok(QueryField::Sha256),
        "embedding" => Ok(QueryField::Embedding),
        "embeddings" => Ok(QueryField::Embeddings),
        "vector" => Ok(QueryField::Vector),
        "score" => Ok(QueryField::Score),
        "corpus" => Ok(QueryField::Corpus),
        "collection" => Ok(QueryField::Collection),
        "architecture" => Ok(QueryField::Architecture),
        "username" => Ok(QueryField::Username),
        "address" => Ok(QueryField::Address),
        "timestamp" => Ok(QueryField::Timestamp),
        "size" => Ok(QueryField::Size),
        "symbol" => Ok(QueryField::Symbol),
        "tag" => Ok(QueryField::Tag),
        "symbols" => Ok(QueryField::Symbols),
        "tags" => Ok(QueryField::Tags),
        "comments" => Ok(QueryField::Comments),
        "cyclomatic_complexity" => Ok(QueryField::CyclomaticComplexity),
        "average_instructions_per_block" => Ok(QueryField::AverageInstructionsPerBlock),
        "instructions" => Ok(QueryField::NumberOfInstructions),
        "blocks" => Ok(QueryField::NumberOfBlocks),
        "markov" => Ok(QueryField::Markov),
        "entropy" => Ok(QueryField::Entropy),
        "contiguous" => Ok(QueryField::Contiguous),
        "chromosome.entropy" => Ok(QueryField::ChromosomeEntropy),
        other => Err(QueryError(format!("unknown search field {}", other))),
    }
}

pub fn query_timestamp_matches(raw: &str, actual: DateTime<Utc>) -> bool {
    let Some(filter) = parse_date_query(raw) else {
        return false;
    };
    match filter.operator {
        DateOperator::Eq => actual >= filter.start && actual < filter.end,
        DateOperator::Gt => actual >= filter.end,
        DateOperator::Gte => actual >= filter.start,
        DateOperator::Lt => actual < filter.start,
        DateOperator::Lte => actual < filter.end,
    }
}

pub fn query_size_matches(raw: &str, actual: u64) -> bool {
    let Some((operator, expected)) = parse_size_query(raw) else {
        return false;
    };
    match operator {
        CountOperator::Eq => actual == expected,
        CountOperator::Gt => actual > expected,
        CountOperator::Gte => actual >= expected,
        CountOperator::Lt => actual < expected,
        CountOperator::Lte => actual <= expected,
    }
}

pub fn query_score_matches(raw: &str, actual: f32) -> bool {
    query_float_matches(raw, actual as f64)
}

pub fn query_integer_matches(raw: &str, actual: u64) -> bool {
    let Some((operator, expected)) = parse_integer_query(raw) else {
        return false;
    };
    match operator {
        CountOperator::Eq => actual == expected,
        CountOperator::Gt => actual > expected,
        CountOperator::Gte => actual >= expected,
        CountOperator::Lt => actual < expected,
        CountOperator::Lte => actual <= expected,
    }
}

pub fn query_float_matches(raw: &str, actual: f64) -> bool {
    let Some((operator, expected)) = parse_score_query(raw) else {
        return false;
    };
    match operator {
        ScoreOperator::Eq => (actual - expected as f64).abs() < f64::EPSILON,
        ScoreOperator::Gt => actual > expected as f64,
        ScoreOperator::Gte => actual >= expected as f64,
        ScoreOperator::Lt => actual < expected as f64,
        ScoreOperator::Lte => actual <= expected as f64,
    }
}

pub fn query_bool_matches(raw: &str, actual: bool) -> bool {
    parse_bool_query(raw) == Some(actual)
}

fn parse_search_query(tokens: &[QueryToken]) -> Result<QueryExpr, QueryError> {
    struct Parser<'a> {
        tokens: &'a [QueryToken],
        index: usize,
    }

    impl<'a> Parser<'a> {
        fn parse_or(&mut self) -> Result<QueryExpr, QueryError> {
            let mut expr = self.parse_and()?;
            while matches!(self.tokens.get(self.index), Some(QueryToken::Or)) {
                self.index += 1;
                let rhs = self
                    .parse_and()
                    .map_err(|_| QueryError("expected a search term after ||".to_string()))?;
                expr = QueryExpr::Or(Box::new(expr), Box::new(rhs));
            }
            Ok(expr)
        }

        fn parse_and(&mut self) -> Result<QueryExpr, QueryError> {
            let mut expr = self.parse_not()?;
            while matches!(self.tokens.get(self.index), Some(QueryToken::And)) {
                self.index += 1;
                let rhs = self
                    .parse_not()
                    .map_err(|_| QueryError("expected a search term after |".to_string()))?;
                expr = QueryExpr::And(Box::new(expr), Box::new(rhs));
            }
            Ok(expr)
        }

        fn parse_not(&mut self) -> Result<QueryExpr, QueryError> {
            if matches!(self.tokens.get(self.index), Some(QueryToken::Not)) {
                self.index += 1;
                if matches!(self.tokens.get(self.index), Some(QueryToken::Not)) {
                    return Err(QueryError(
                        "consecutive ! operators are not allowed".to_string(),
                    ));
                }
                return Ok(QueryExpr::Not(Box::new(self.parse_not().map_err(
                    |_| QueryError("expected a search term after !".to_string()),
                )?)));
            }
            self.parse_primary()
        }

        fn parse_primary(&mut self) -> Result<QueryExpr, QueryError> {
            match self.tokens.get(self.index) {
                Some(QueryToken::Term(term)) => {
                    self.index += 1;
                    Ok(QueryExpr::Term(term.clone()))
                }
                Some(QueryToken::LParen) => {
                    self.index += 1;
                    if matches!(self.tokens.get(self.index), Some(QueryToken::RParen) | None) {
                        return Err(QueryError(
                            "expected a search term inside parenthesis".to_string(),
                        ));
                    }
                    let expr = self.parse_or().map_err(|_| {
                        QueryError("expected a search term inside parenthesis".to_string())
                    })?;
                    match self.tokens.get(self.index) {
                        Some(QueryToken::RParen) => {
                            self.index += 1;
                            Ok(expr)
                        }
                        _ => Err(QueryError("unclosed parenthesis".to_string())),
                    }
                }
                Some(_) => Err(QueryError("expected a search term".to_string())),
                None if self.index == 0 => Err(QueryError("enter a search query".to_string())),
                None => Err(QueryError("expected a search term".to_string())),
            }
        }
    }

    let mut parser = Parser { tokens, index: 0 };
    let expr = parser.parse_or()?;
    if parser.index != tokens.len() {
        return Err(QueryError(
            "unexpected trailing tokens in query".to_string(),
        ));
    }
    Ok(expr)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn parse_query_vector(value: &str) -> Option<Vec<f32>> {
    let trimmed = value.trim();
    if trimmed.is_empty() || !trimmed.starts_with('[') {
        return None;
    }

    let parsed: serde_json::Value = serde_json::from_str(trimmed).ok()?;
    let values = parsed.as_array()?;
    if values.len() < 2 {
        return None;
    }
    values
        .iter()
        .map(|item| item.as_f64().map(|number| number as f32))
        .collect()
}

fn parse_integer_query(raw: &str) -> Option<(CountOperator, u64)> {
    parse_count_query(raw)
}

fn parse_positive_count_query(raw: &str) -> Option<(CountOperator, u64)> {
    let (operator, value) = parse_count_query(raw)?;
    if value == 0 {
        return None;
    }
    Some((operator, value))
}

fn parse_float_query(raw: &str) -> Option<(ScoreOperator, f32)> {
    parse_score_query(raw)
}

fn parse_bool_query(raw: &str) -> Option<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

fn parse_query_address(value: &str) -> Option<u64> {
    let trimmed = value.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16).ok();
    }
    trimmed.parse::<u64>().ok()
}

fn parse_count_query(raw: &str) -> Option<(CountOperator, u64)> {
    let trimmed = raw.trim();
    let (operator, remainder) = if let Some(value) = trimmed.strip_prefix(">=") {
        (CountOperator::Gte, value)
    } else if let Some(value) = trimmed.strip_prefix("<=") {
        (CountOperator::Lte, value)
    } else if let Some(value) = trimmed.strip_prefix('>') {
        (CountOperator::Gt, value)
    } else if let Some(value) = trimmed.strip_prefix('<') {
        (CountOperator::Lt, value)
    } else if let Some(value) = trimmed.strip_prefix('=') {
        (CountOperator::Eq, value)
    } else {
        (CountOperator::Eq, trimmed)
    };
    parse_compact_count(remainder).map(|value| (operator, value))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CountOperator {
    Eq,
    Gt,
    Gte,
    Lt,
    Lte,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DateOperator {
    Eq,
    Gt,
    Gte,
    Lt,
    Lte,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum ScoreOperator {
    Eq,
    Gt,
    Gte,
    Lt,
    Lte,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DateFilter {
    operator: DateOperator,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
}

fn parse_date_query(raw: &str) -> Option<DateFilter> {
    let trimmed = raw.trim();
    let (operator, remainder) = if let Some(value) = trimmed.strip_prefix(">=") {
        (DateOperator::Gte, value)
    } else if let Some(value) = trimmed.strip_prefix("<=") {
        (DateOperator::Lte, value)
    } else if let Some(value) = trimmed.strip_prefix('>') {
        (DateOperator::Gt, value)
    } else if let Some(value) = trimmed.strip_prefix('<') {
        (DateOperator::Lt, value)
    } else if let Some(value) = trimmed.strip_prefix('=') {
        (DateOperator::Eq, value)
    } else {
        (DateOperator::Eq, trimmed)
    };
    let value = remainder.trim();
    let (start, end) = parse_date_span(value)?;
    Some(DateFilter {
        operator,
        start,
        end,
    })
}

fn parse_date_span(raw: &str) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
    let trimmed = raw.trim();
    if trimmed.len() == 4 {
        let year = trimmed.parse::<i32>().ok()?;
        let start = Utc.with_ymd_and_hms(year, 1, 1, 0, 0, 0).single()?;
        let end = Utc.with_ymd_and_hms(year + 1, 1, 1, 0, 0, 0).single()?;
        return Some((start, end));
    }
    if trimmed.len() == 7 {
        let date = NaiveDate::parse_from_str(&format!("{trimmed}-01"), "%Y-%m-%d").ok()?;
        let start = Utc.from_utc_datetime(&date.and_hms_opt(0, 0, 0)?);
        let next = date.checked_add_months(Months::new(1))?;
        let end = Utc.from_utc_datetime(&next.and_hms_opt(0, 0, 0)?);
        return Some((start, end));
    }
    if trimmed.len() == 10 {
        let date = NaiveDate::parse_from_str(trimmed, "%Y-%m-%d").ok()?;
        let start = Utc.from_utc_datetime(&date.and_hms_opt(0, 0, 0)?);
        let end = start.checked_add_signed(Duration::days(1))?;
        return Some((start, end));
    }
    None
}

fn parse_size_query(raw: &str) -> Option<(CountOperator, u64)> {
    let trimmed = raw.trim();
    let (operator, remainder) = if let Some(value) = trimmed.strip_prefix(">=") {
        (CountOperator::Gte, value)
    } else if let Some(value) = trimmed.strip_prefix("<=") {
        (CountOperator::Lte, value)
    } else if let Some(value) = trimmed.strip_prefix('>') {
        (CountOperator::Gt, value)
    } else if let Some(value) = trimmed.strip_prefix('<') {
        (CountOperator::Lt, value)
    } else if let Some(value) = trimmed.strip_prefix('=') {
        (CountOperator::Eq, value)
    } else {
        (CountOperator::Eq, trimmed)
    };
    parse_size_bytes(remainder).map(|value| (operator, value))
}

fn parse_score_query(raw: &str) -> Option<(ScoreOperator, f32)> {
    let trimmed = raw.trim();
    let (operator, remainder) = if let Some(value) = trimmed.strip_prefix(">=") {
        (ScoreOperator::Gte, value)
    } else if let Some(value) = trimmed.strip_prefix("<=") {
        (ScoreOperator::Lte, value)
    } else if let Some(value) = trimmed.strip_prefix('>') {
        (ScoreOperator::Gt, value)
    } else if let Some(value) = trimmed.strip_prefix('<') {
        (ScoreOperator::Lt, value)
    } else if let Some(value) = trimmed.strip_prefix('=') {
        (ScoreOperator::Eq, value)
    } else {
        (ScoreOperator::Eq, trimmed)
    };
    let value = remainder.trim().parse::<f32>().ok()?;
    if !value.is_finite() {
        return None;
    }
    Some((operator, value))
}

fn parse_size_bytes(raw: &str) -> Option<u64> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    let (number, multiplier) = if let Some(value) = lower.strip_suffix("kb") {
        (value, 1024f64)
    } else if let Some(value) = lower.strip_suffix("mb") {
        (value, 1024f64 * 1024f64)
    } else if let Some(value) = lower.strip_suffix("gb") {
        (value, 1024f64 * 1024f64 * 1024f64)
    } else if let Some(value) = lower.strip_suffix('b') {
        (value, 1f64)
    } else {
        (lower.as_str(), 1f64)
    };
    let value = number.trim().parse::<f64>().ok()?;
    if !value.is_finite() || value < 0.0 {
        return None;
    }
    let scaled = value * multiplier;
    if scaled > u64::MAX as f64 {
        return None;
    }
    Some(scaled.round() as u64)
}

fn parse_compact_count(raw: &str) -> Option<u64> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    let (number, multiplier) = match lower.chars().last() {
        Some('k') => (&lower[..lower.len() - 1], 1_000f64),
        Some('m') => (&lower[..lower.len() - 1], 1_000_000f64),
        Some('b') => (&lower[..lower.len() - 1], 1_000_000_000f64),
        _ => (lower.as_str(), 1f64),
    };
    let value = number.trim().parse::<f64>().ok()?;
    if !value.is_finite() || value < 0.0 {
        return None;
    }
    let scaled = value * multiplier;
    if scaled > u64::MAX as f64 {
        return None;
    }
    Some(scaled.round() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenizer_preserves_vector_json_array() {
        let query = Query::parse("vector: [0.1, -0.2, 0.3] | collection: functions").unwrap();
        match query.expr() {
            QueryExpr::And(lhs, _) => match lhs.as_ref() {
                QueryExpr::Term(term) => {
                    assert_eq!(term.field, QueryField::Vector);
                    assert_eq!(term.value, "[0.1, -0.2, 0.3]");
                }
                other => panic!("unexpected lhs: {:?}", other),
            },
            other => panic!("unexpected expr: {:?}", other),
        }
    }

    #[test]
    fn tokenizer_supports_embedding_field() {
        let query = Query::parse(
            "embedding: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        match query.expr() {
            QueryExpr::Term(term) => {
                assert_eq!(term.field, QueryField::Embedding);
                assert_eq!(
                    term.value,
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                );
            }
            other => panic!("unexpected token: {:?}", other),
        }
    }

    #[test]
    fn tokenizer_accepts_terms_without_space_after_colon() {
        let query = Query::parse("collection:functions | architecture:amd64").unwrap();
        match query.expr() {
            QueryExpr::And(lhs, rhs) => {
                match lhs.as_ref() {
                    QueryExpr::Term(term) => {
                        assert_eq!(term.field, QueryField::Collection);
                        assert_eq!(term.value, "functions");
                    }
                    other => panic!("unexpected lhs: {:?}", other),
                }
                match rhs.as_ref() {
                    QueryExpr::Term(term) => {
                        assert_eq!(term.field, QueryField::Architecture);
                        assert_eq!(term.value, "amd64");
                    }
                    other => panic!("unexpected rhs: {:?}", other),
                }
            }
            other => panic!("unexpected expr: {:?}", other),
        }
    }

    #[test]
    fn tokenizer_accepts_space_before_colon() {
        let query = Query::parse("collection : functions | architecture : amd64").unwrap();
        match query.expr() {
            QueryExpr::And(lhs, rhs) => {
                match lhs.as_ref() {
                    QueryExpr::Term(term) => {
                        assert_eq!(term.field, QueryField::Collection);
                        assert_eq!(term.value, "functions");
                    }
                    other => panic!("unexpected lhs: {:?}", other),
                }
                match rhs.as_ref() {
                    QueryExpr::Term(term) => {
                        assert_eq!(term.field, QueryField::Architecture);
                        assert_eq!(term.value, "amd64");
                    }
                    other => panic!("unexpected rhs: {:?}", other),
                }
            }
            other => panic!("unexpected expr: {:?}", other),
        }
    }

    #[test]
    fn parser_gives_and_higher_precedence_than_or() {
        let query = Query::parse("symbol: \"a\" || symbol: \"b\" | corpus: default").unwrap();
        match query.expr() {
            QueryExpr::Or(_, rhs) => match rhs.as_ref() {
                QueryExpr::And(_, _) => {}
                other => panic!("unexpected rhs: {:?}", other),
            },
            other => panic!("unexpected expr: {:?}", other),
        }
    }

    #[test]
    fn root_terms_are_rejected_inside_or() {
        let query = Query::parse(
            "lhs: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef || corpus: default",
        )
        .unwrap();
        let error = query.analyze().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("sha256 queries can only be combined with `|`")
        );
    }

    #[test]
    fn embedding_root_terms_are_rejected_inside_or() {
        let query = Query::parse(
            "embedding: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef || corpus: default",
        )
        .unwrap();
        let error = query.analyze().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("embedding queries can only be combined with `|`")
        );
    }

    #[test]
    fn negated_sha256_is_allowed_with_vector_root() {
        let query = Query::parse(
            "vector: [0.1, 0.2] | collection: functions | architecture: amd64 | !lhs: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        let analysis = query.analyze().unwrap();
        assert!(matches!(analysis.root, Some(SearchRoot::Vector(_))));
    }

    #[test]
    fn negated_sha256_or_group_is_allowed_with_vector_root() {
        let query = Query::parse(
            "vector: [0.1, 0.2] | collection: functions | architecture: amd64 | !(lhs: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef || rhs: fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210)",
        )
        .unwrap();
        let analysis = query.analyze().unwrap();
        assert!(matches!(analysis.root, Some(SearchRoot::Vector(_))));
    }

    #[test]
    fn symbol_requires_quoted_string() {
        let error = Query::parse("symbol: kernel32:CreateFileW").unwrap_err();
        assert!(error.to_string().contains("quoted string"));
    }

    #[test]
    fn symbol_supports_escaped_quotes() {
        let query = Query::parse(r#"symbol:"a\"b""#).unwrap();
        match query.expr() {
            QueryExpr::Term(term) => {
                assert_eq!(term.field, QueryField::Symbol);
                assert_eq!(term.value, "a\"b");
            }
            other => panic!("unexpected expr: {:?}", other),
        }
    }

    #[test]
    fn username_parses_as_simple_filter() {
        let query = Query::parse("username:anonymous").unwrap();
        match query.expr() {
            QueryExpr::Term(term) => {
                assert_eq!(term.field, QueryField::Username);
                assert_eq!(term.value, "anonymous");
            }
            other => panic!("unexpected expr: {:?}", other),
        }
    }

    #[test]
    fn analyze_returns_language_level_filters() {
        let query = Query::parse(
            "embedding: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef | corpus: default | collection:functions | architecture:amd64",
        )
        .unwrap();
        let analysis = query.analyze().unwrap();
        assert_eq!(analysis.corpora, vec!["default".to_string()]);
        assert_eq!(analysis.collections, vec![QueryCollection::Function]);
        assert_eq!(analysis.architectures, vec![Architecture::AMD64]);
        assert!(matches!(analysis.root, Some(SearchRoot::Embedding(_))));
    }

    #[test]
    fn embeddings_reject_invalid_count_syntax() {
        let query = Query::parse("embeddings:>>1k").unwrap();
        let error = query.analyze().unwrap_err();
        assert!(error.to_string().contains("embeddings expects counts"));
    }

    #[test]
    fn embeddings_reject_zero_counts() {
        for raw in [
            "embeddings:0",
            "embeddings:=0",
            "embeddings:>0",
            "embeddings:<0",
        ] {
            let query = Query::parse(raw).unwrap();
            let error = query.analyze().unwrap_err();
            assert!(error.to_string().contains("embeddings expects counts"));
        }
    }

    #[test]
    fn entity_count_filters_accept_zero_bounds() {
        for raw in [
            "symbols:>0",
            "symbols:>=0",
            "tags:>0",
            "tags:>=0",
            "comments:>=0",
        ] {
            Query::parse(raw).unwrap().analyze().unwrap();
        }
    }

    #[test]
    fn date_accepts_supported_forms() {
        for raw in [
            "timestamp:2026",
            "timestamp:2026-03",
            "timestamp:2026-03-30",
            "timestamp:>=2026-03-01",
            "timestamp:<=2026-03-31",
        ] {
            Query::parse(raw).unwrap().analyze().unwrap();
        }
    }

    #[test]
    fn date_rejects_invalid_forms() {
        for raw in [
            "timestamp:2026-3",
            "timestamp:2026-03-3",
            "timestamp:2026-13",
            "timestamp:bogus",
        ] {
            let query = Query::parse(raw).unwrap();
            let error = query.analyze().unwrap_err();
            assert!(error.to_string().contains("timestamp expects"));
        }
    }

    #[test]
    fn date_filter_matches_exact_and_comparison_forms() {
        let actual = Utc
            .with_ymd_and_hms(2026, 3, 30, 18, 25, 0)
            .single()
            .unwrap();
        assert!(query_timestamp_matches("2026", actual));
        assert!(query_timestamp_matches("2026-03", actual));
        assert!(query_timestamp_matches("2026-03-30", actual));
        assert!(query_timestamp_matches(">=2026-03-01", actual));
        assert!(query_timestamp_matches("<=2026-03-31", actual));
        assert!(!query_timestamp_matches("<2026-03", actual));
        assert!(!query_timestamp_matches(">2026-03", actual));
        assert!(!query_timestamp_matches("2026-04", actual));
    }

    #[test]
    fn size_accepts_supported_forms() {
        for raw in ["size:32", "size:>64", "size:>=1kb", "size:<1mb"] {
            Query::parse(raw).unwrap().analyze().unwrap();
        }
    }

    #[test]
    fn size_rejects_invalid_forms() {
        let query = Query::parse("size:>1tb").unwrap();
        let error = query.analyze().unwrap_err();
        assert!(error.to_string().contains("size expects"));
    }

    #[test]
    fn size_filter_matches_comparison_forms() {
        assert!(query_size_matches("32", 32));
        assert!(query_size_matches(">64", 65));
        assert!(query_size_matches(">=1kb", 1024));
        assert!(query_size_matches("<1mb", 1024));
        assert!(!query_size_matches(">1mb", 1024));
    }

    #[test]
    fn score_accepts_supported_forms() {
        for raw in ["score:0.95", "score:>0.9", "score:>=1.0", "score:<0.5"] {
            Query::parse(raw).unwrap().analyze().unwrap();
        }
    }

    #[test]
    fn score_rejects_invalid_forms() {
        let query = Query::parse("score:bogus").unwrap();
        let error = query.analyze().unwrap_err();
        assert!(error.to_string().contains("score expects"));
    }

    #[test]
    fn score_filter_matches_comparison_forms() {
        assert!(query_score_matches("0.95", 0.95));
        assert!(query_score_matches(">0.9", 0.95));
        assert!(query_score_matches(">=0.95", 0.95));
        assert!(query_score_matches("<1.0", 0.95));
        assert!(!query_score_matches(">1.0", 0.95));
    }

    #[test]
    fn structural_metric_filters_accept_supported_forms() {
        for raw in [
            "sample:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef | cyclomatic_complexity:1",
            "sample:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef | average_instructions_per_block:>0",
            "sample:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef | instructions:1",
            "sample:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef | blocks:1",
            "sample:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef | markov:>0",
            "sample:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef | entropy:>0",
            "sample:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef | contiguous:true",
            "sample:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef | chromosome.entropy:>0",
        ] {
            Query::parse(raw).unwrap().analyze().unwrap();
        }
    }

    #[test]
    fn address_rejects_invalid_syntax() {
        let query = Query::parse("address:xyz").unwrap();
        let error = query.analyze().unwrap_err();
        assert_eq!(error.to_string(), "invalid address xyz");
    }

    #[test]
    fn incomplete_and_reports_specific_error() {
        let error = Query::parse("collection:functions |").unwrap_err();
        assert_eq!(error.to_string(), "expected a search term after |");
    }

    #[test]
    fn incomplete_not_reports_specific_error() {
        let error = Query::parse("collection:functions | !").unwrap_err();
        assert_eq!(error.to_string(), "expected a search term after |");
    }

    #[test]
    fn incomplete_parenthesis_reports_specific_error() {
        let error = Query::parse("collection:functions | !(").unwrap_err();
        assert_eq!(error.to_string(), "expected a search term after |");
    }

    #[test]
    fn empty_parenthesis_reports_specific_error() {
        let error = Query::parse("collection:functions | !( )").unwrap_err();
        assert_eq!(error.to_string(), "expected a search term after |");
    }

    #[test]
    fn bare_not_group_reports_specific_error() {
        let error = Query::parse("!(").unwrap_err();
        assert_eq!(error.to_string(), "expected a search term after !");
    }

    #[test]
    fn consecutive_not_is_rejected() {
        let error = Query::parse("lhs:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef | ! !collection:functions")
            .unwrap_err();
        assert_eq!(error.to_string(), "expected a search term after |");
    }
}
