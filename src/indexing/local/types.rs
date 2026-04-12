use super::support::parse_timestamp;
use crate::controlflow::GraphSnapshot;
use crate::databases::{
    CollectionCommentRecord as DatabaseCollectionCommentRecord,
    CollectionTagRecord as DatabaseCollectionTagRecord,
    EntityCommentRecord as DatabaseEntityCommentRecord,
    EntityCommentSearchPage as DatabaseEntityCommentSearchPage,
    SampleStatusRecord as DatabaseSampleStatusRecord,
};
use crate::indexing::Collection;
use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt;

use crate::databases::localdb::EntityChildWrite;

#[derive(Debug)]
pub enum Error {
    InvalidConfiguration(&'static str),
    Validation(String),
    Serialization(String),
    Graph(String),
    NotFound(String),
    LocalStore(String),
    LanceDb(String),
    LocalDb(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(message) => {
                write!(f, "local index configuration error: {}", message)
            }
            Self::Validation(message) => {
                write!(f, "local index configuration error: {}", message)
            }
            Self::Serialization(message) => {
                write!(f, "local index serialization error: {}", message)
            }
            Self::Graph(message) => write!(f, "local index graph error: {}", message),
            Self::NotFound(message) => write!(f, "local index not found: {}", message),
            Self::LocalStore(message) => write!(f, "local index local store error: {}", message),
            Self::LanceDb(message) => write!(f, "local index lancedb error: {}", message),
            Self::LocalDb(message) => write!(f, "local index localdb error: {}", message),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct StoredGraphRecord {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) attributes: Option<Value>,
    pub(super) snapshot: GraphSnapshot,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct IndexEntry {
    pub(super) object_id: String,
    pub(super) entity: Collection,
    pub(super) architecture: String,
    #[serde(default = "default_index_username")]
    pub(super) username: String,
    pub(super) sha256: String,
    pub(super) address: u64,
    pub(super) size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) cyclomatic_complexity: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) average_instructions_per_block: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) number_of_instructions: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) number_of_blocks: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) markov: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) entropy: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) contiguous: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) chromosome_entropy: Option<f64>,
    #[serde(default)]
    pub(super) collection_tag_count: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) collection_tags: Vec<String>,
    #[serde(default)]
    pub(super) collection_comment_count: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(super) timestamp: String,
    pub(super) vector: Vec<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) explicit_corpora: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) attributes: Vec<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) json: Option<Value>,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub(super) struct EntityMetrics {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) cyclomatic_complexity: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) average_instructions_per_block: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) number_of_instructions: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) number_of_blocks: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) markov: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) entropy: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) contiguous: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) chromosome_entropy: Option<f64>,
}

#[derive(Clone, Default)]
pub(super) struct PendingBatch {
    pub(super) graphs: BTreeMap<String, StoredGraphRecord>,
    pub(super) entries: BTreeMap<String, IndexEntry>,
    pub(super) entity_corpora: BTreeMap<String, Vec<String>>,
    pub(super) entity_children: BTreeMap<String, EntityChildWrite>,
    pub(super) deleted_samples: Vec<(String, String)>,
    pub(super) deleted_corpora: Vec<String>,
}

pub(super) const DEFAULT_INDEX_GRAPH_COLLECTIONS: &[Collection] =
    &[Collection::Block, Collection::Function];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TagRecord {
    pub sha256: String,
    pub tag: String,
    pub timestamp: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommentRecord {
    pub sha256: String,
    pub comment: String,
    pub timestamp: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TagSearchPage {
    pub items: Vec<TagRecord>,
    pub page: usize,
    pub page_size: usize,
    pub has_next: bool,
}

pub type CollectionTagRecord = DatabaseCollectionTagRecord;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectionTagSearchPage {
    pub items: Vec<CollectionTagRecord>,
    pub page: usize,
    pub page_size: usize,
    pub has_next: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommentSearchPage {
    pub items: Vec<CommentRecord>,
    pub page: usize,
    pub page_size: usize,
    pub has_next: bool,
}

pub type CollectionCommentRecord = DatabaseCollectionCommentRecord;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectionCommentSearchPage {
    pub items: Vec<CollectionCommentRecord>,
    pub page: usize,
    pub page_size: usize,
    pub has_next: bool,
}

pub type EntityCommentRecord = DatabaseEntityCommentRecord;
pub type EntityCommentSearchPage = DatabaseEntityCommentSearchPage;

pub type SampleStatusRecord = DatabaseSampleStatusRecord;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SearchResult {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) corpora: Vec<String>,
    pub(super) object_id: String,
    pub(super) entity: Collection,
    pub(super) architecture: String,
    #[serde(default = "default_index_username")]
    pub(super) username: String,
    pub(super) sha256: String,
    pub(super) address: u64,
    pub(super) size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) cyclomatic_complexity: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) average_instructions_per_block: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) number_of_instructions: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) number_of_blocks: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) markov: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) entropy: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) contiguous: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) chromosome_entropy: Option<f64>,
    #[serde(default)]
    pub(super) collection_tag_count: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) collection_tags: Vec<String>,
    #[serde(default)]
    pub(super) collection_comment_count: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(super) timestamp: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) symbol: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) attributes: Vec<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) vector: Vec<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) json: Option<Value>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(super) embedding: String,
    #[serde(default)]
    pub(super) embeddings: u64,
    pub(super) score: f32,
}

impl SearchResult {
    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn corpus(&self) -> &str {
        self.corpora.first().map(String::as_str).unwrap_or("")
    }

    pub fn corpora(&self) -> &[String] {
        &self.corpora
    }

    pub fn object_id(&self) -> &str {
        &self.object_id
    }

    pub fn collection(&self) -> Collection {
        self.entity
    }

    pub fn architecture(&self) -> &str {
        &self.architecture
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn address(&self) -> u64 {
        self.address
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn cyclomatic_complexity(&self) -> Option<u64> {
        self.cyclomatic_complexity
    }

    pub fn average_instructions_per_block(&self) -> Option<f64> {
        self.average_instructions_per_block
    }

    pub fn number_of_instructions(&self) -> Option<u64> {
        self.number_of_instructions
    }

    pub fn number_of_blocks(&self) -> Option<u64> {
        self.number_of_blocks
    }

    pub fn markov(&self) -> Option<f64> {
        self.markov
    }

    pub fn entropy(&self) -> Option<f64> {
        self.entropy
    }

    pub fn contiguous(&self) -> Option<bool> {
        self.contiguous
    }

    pub fn chromosome_entropy(&self) -> Option<f64> {
        self.chromosome_entropy
    }

    pub fn collection_comment_count(&self) -> u64 {
        self.collection_comment_count
    }

    pub fn collection_tag_count(&self) -> u64 {
        self.collection_tag_count
    }

    pub fn collection_tags(&self) -> &[String] {
        &self.collection_tags
    }

    pub fn symbol_count(&self) -> u64 {
        super::support::symbol_names_for_attributes(&self.attributes, self.entity, self.address)
            .len() as u64
    }

    pub fn timestamp(&self) -> DateTime<Utc> {
        parse_timestamp(&self.timestamp).unwrap_or_else(|| {
            Utc.timestamp_opt(0, 0)
                .single()
                .expect("unix epoch is valid")
        })
    }

    pub fn symbol(&self) -> Option<&str> {
        self.symbol.as_deref()
    }

    pub fn attributes(&self) -> &[Value] {
        &self.attributes
    }

    pub fn score(&self) -> f32 {
        self.score
    }

    pub fn with_score(mut self, score: f32) -> Self {
        self.score = score;
        self
    }

    pub fn vector(&self) -> &[f32] {
        &self.vector
    }

    pub fn json(&self) -> Option<&Value> {
        self.json.as_ref()
    }

    pub fn embedding(&self) -> &str {
        &self.embedding
    }

    pub fn embeddings(&self) -> u64 {
        self.embeddings
    }
}

fn default_index_username() -> String {
    "anonymous".to_string()
}
