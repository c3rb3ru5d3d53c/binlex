use crate::Architecture;
use crate::indexing::Collection;
use serde::Serialize;
use std::fmt;

#[derive(Clone, Debug, Serialize)]
pub struct Query {
    pub(super) raw: String,
    pub(super) expr: QueryExpr,
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
pub(super) enum QueryToken {
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
