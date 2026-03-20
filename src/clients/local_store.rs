use crate::Config;
use crate::clients::{lancedb, object_store};
use crate::controlflow::{Block, Function, Graph, GraphSnapshot, Instruction};
use crate::metadata::Attributes;
use crate::processor::GraphProcessor;
use crate::processors::embeddings::EmbeddingsProcessor;
use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Collection {
    Instruction,
    Block,
    Function,
}

impl Collection {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Instruction => "instruction",
            Self::Block => "block",
            Self::Function => "function",
        }
    }
}

impl fmt::Display for Collection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone)]
pub struct Client {
    config: Config,
    object_store: object_store::Client,
    lancedb: lancedb::Client,
}

#[derive(Debug)]
pub enum Error {
    InvalidConfiguration(&'static str),
    Serialization(String),
    Graph(String),
    NotFound(String),
    ObjectStore(String),
    LanceDb(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(message) => {
                write!(f, "local store configuration error: {}", message)
            }
            Self::Serialization(message) => {
                write!(f, "local store serialization error: {}", message)
            }
            Self::Graph(message) => write!(f, "local store graph error: {}", message),
            Self::NotFound(message) => write!(f, "local store not found: {}", message),
            Self::ObjectStore(message) => write!(f, "local store object store error: {}", message),
            Self::LanceDb(message) => write!(f, "local store lancedb error: {}", message),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Serialize, Deserialize)]
struct StoredGraphRecord {
    sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    attributes: Option<Value>,
    snapshot: GraphSnapshot,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Occurrence {
    sha256: String,
    address: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct IndexEntry {
    object_id: String,
    collection: Collection,
    architecture: String,
    vector: Vec<f32>,
    occurrences: Vec<Occurrence>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SearchHit {
    pub corpus: String,
    pub object_id: String,
    pub collection: Collection,
    pub architecture: String,
    pub sha256: String,
    pub address: u64,
    pub score: f32,
}

impl Client {
    pub fn new(root: impl Into<PathBuf>, config: Config) -> Result<Self, Error> {
        let root = root.into();
        if root.as_os_str().is_empty() {
            return Err(Error::InvalidConfiguration("root must not be empty"));
        }
        Ok(Self {
            config,
            object_store: object_store::Client::new(root.join("object_store"))
                .map_err(|error| Error::ObjectStore(error.to_string()))?,
            lancedb: lancedb::Client::new(root.join("lancedb"))
                .map_err(|error| Error::LanceDb(error.to_string()))?,
        })
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn put(&self, data: &[u8]) -> Result<String, Error> {
        let sha256 = digest_hex(data);
        let key = sample_key(&sha256);
        if self
            .object_store
            .exists(&key)
            .map_err(|error| Error::ObjectStore(error.to_string()))?
        {
            return Ok(sha256);
        }
        self.object_store
            .put_bytes(&key, data)
            .map_err(|error| Error::ObjectStore(error.to_string()))?;
        Ok(sha256)
    }

    pub fn get(&self, sha256: &str) -> Result<Vec<u8>, Error> {
        self.object_store
            .get_bytes(&sample_key(sha256))
            .map_err(|error| match error {
                object_store::Error::NotFound(_) => Error::NotFound(format!("sample {}", sha256)),
                other => Error::ObjectStore(other.to_string()),
            })
    }

    pub fn index(
        &self,
        corpus: &str,
        sha256: &str,
        graph: &Graph,
        attributes: Option<&Attributes>,
    ) -> Result<(), Error> {
        self.index_json_attributes(corpus, sha256, graph, attributes.map(Attributes::process))
    }

    pub fn index_json_attributes(
        &self,
        corpus: &str,
        sha256: &str,
        graph: &Graph,
        attributes: Option<Value>,
    ) -> Result<(), Error> {
        if corpus.trim().is_empty() {
            return Err(Error::InvalidConfiguration("corpus must not be empty"));
        }
        if sha256.trim().is_empty() {
            return Err(Error::InvalidConfiguration("sha256 must not be empty"));
        }

        let record = StoredGraphRecord {
            sha256: sha256.to_string(),
            attributes,
            snapshot: graph.snapshot(),
        };
        self.object_store
            .put_json(&graph_key(corpus, sha256), &record)
            .map_err(|error| Error::ObjectStore(error.to_string()))?;

        self.index_instructions(corpus, sha256, graph)?;
        self.index_blocks(corpus, sha256, graph)?;
        self.index_functions(corpus, sha256, graph)?;
        Ok(())
    }

    pub fn graph(&self, corpus: &str, sha256: &str) -> Result<Graph, Error> {
        let record: StoredGraphRecord = self
            .object_store
            .get_json(&graph_key(corpus, sha256))
            .map_err(|error| match error {
                object_store::Error::NotFound(_) => {
                    Error::NotFound(format!("graph {}/{}", corpus, sha256))
                }
                other => Error::ObjectStore(other.to_string()),
            })?;
        Graph::from_snapshot(record.snapshot, self.config.clone())
            .map_err(|error| Error::Graph(error.to_string()))
    }

    pub fn search(
        &self,
        corpus: &str,
        collection: Collection,
        architecture: crate::Architecture,
        vector: &[f32],
        limit: usize,
    ) -> Result<Vec<SearchHit>, Error> {
        if corpus.trim().is_empty() {
            return Err(Error::InvalidConfiguration("corpus must not be empty"));
        }
        let rows = self
            .lancedb
            .search(corpus, collection, &architecture.to_string(), vector, limit)
            .map_err(|error| Error::LanceDb(error.to_string()))?;
        let mut hits = Vec::new();
        for row in rows {
            let occurrences: Vec<Occurrence> = serde_json::from_str(&row.occurrences_json)
                .map_err(|error| Error::Serialization(error.to_string()))?;
            let score = cosine_similarity(vector, &row.vector);
            for occurrence in occurrences {
                hits.push(SearchHit {
                    corpus: corpus.to_string(),
                    object_id: row.object_id.clone(),
                    collection,
                    architecture: architecture.to_string(),
                    sha256: occurrence.sha256,
                    address: occurrence.address,
                    score,
                });
            }
        }
        hits.sort_by(|lhs, rhs| rhs.score.total_cmp(&lhs.score));
        if hits.len() > limit {
            hits.truncate(limit);
        }
        Ok(hits)
    }

    fn index_instructions(&self, corpus: &str, sha256: &str, graph: &Graph) -> Result<(), Error> {
        for instruction in graph.instructions() {
            let Some(vector) = instruction_vector(&instruction) else {
                continue;
            };
            let object_id = object_id_for_value(
                Collection::Instruction,
                &instruction_canonical_value(&instruction)?,
            );
            self.upsert_entry(
                corpus,
                Collection::Instruction,
                &graph.architecture.to_string(),
                &object_id,
                vector,
                Occurrence {
                    sha256: sha256.to_string(),
                    address: instruction.address,
                },
            )?;
        }
        Ok(())
    }

    fn index_blocks(&self, corpus: &str, sha256: &str, graph: &Graph) -> Result<(), Error> {
        for block in graph.blocks() {
            let Some(vector) = block_vector(&block) else {
                continue;
            };
            let object_id = object_id_for_value(Collection::Block, &block_canonical_value(&block)?);
            self.upsert_entry(
                corpus,
                Collection::Block,
                &graph.architecture.to_string(),
                &object_id,
                vector,
                Occurrence {
                    sha256: sha256.to_string(),
                    address: block.address(),
                },
            )?;
        }
        Ok(())
    }

    fn index_functions(&self, corpus: &str, sha256: &str, graph: &Graph) -> Result<(), Error> {
        for function in graph.functions() {
            let Some(vector) = function_vector(&function) else {
                continue;
            };
            let object_id =
                object_id_for_value(Collection::Function, &function_canonical_value(&function)?);
            self.upsert_entry(
                corpus,
                Collection::Function,
                &graph.architecture.to_string(),
                &object_id,
                vector,
                Occurrence {
                    sha256: sha256.to_string(),
                    address: function.address,
                },
            )?;
        }
        Ok(())
    }

    fn upsert_entry(
        &self,
        corpus: &str,
        collection: Collection,
        architecture: &str,
        object_id: &str,
        vector: Vec<f32>,
        occurrence: Occurrence,
    ) -> Result<(), Error> {
        let key = index_entry_key(corpus, collection, architecture, object_id);
        let mut entry = match self.object_store.get_json::<IndexEntry>(&key) {
            Ok(existing) => existing,
            Err(object_store::Error::NotFound(_)) => IndexEntry {
                object_id: object_id.to_string(),
                collection,
                architecture: architecture.to_string(),
                vector: vector.clone(),
                occurrences: Vec::new(),
            },
            Err(error) => return Err(Error::ObjectStore(error.to_string())),
        };

        if !entry.occurrences.iter().any(|existing| {
            existing.sha256 == occurrence.sha256 && existing.address == occurrence.address
        }) {
            entry.occurrences.push(occurrence);
        }
        entry.vector = vector;

        self.object_store
            .put_json(&key, &entry)
            .map_err(|error| Error::ObjectStore(error.to_string()))?;
        let occurrences_json = serde_json::to_string(&entry.occurrences)
            .map_err(|error| Error::Serialization(error.to_string()))?;
        self.lancedb
            .upsert(
                corpus,
                collection,
                architecture,
                object_id,
                &entry.vector,
                &occurrences_json,
            )
            .map_err(|error| Error::LanceDb(error.to_string()))
    }
}

fn digest_hex(data: &[u8]) -> String {
    crate::hex::encode(digest(&SHA256, data).as_ref())
}

fn cosine_similarity(lhs: &[f32], rhs: &[f32]) -> f32 {
    if lhs.is_empty() || rhs.is_empty() || lhs.len() != rhs.len() {
        return 0.0;
    }
    let mut dot = 0.0f32;
    let mut lhs_norm = 0.0f32;
    let mut rhs_norm = 0.0f32;
    for (l, r) in lhs.iter().zip(rhs) {
        dot += l * r;
        lhs_norm += l * l;
        rhs_norm += r * r;
    }
    if lhs_norm == 0.0 || rhs_norm == 0.0 {
        return 0.0;
    }
    dot / (lhs_norm.sqrt() * rhs_norm.sqrt())
}

fn embedding_vector(output: Value) -> Option<Vec<f32>> {
    let vector = output.get("vector")?.as_array()?;
    vector
        .iter()
        .map(|value| value.as_f64().map(|item| item as f32))
        .collect()
}

fn instruction_vector(instruction: &Instruction) -> Option<Vec<f32>> {
    let output = <EmbeddingsProcessor as GraphProcessor>::instruction(instruction)?;
    embedding_vector(output)
}

fn block_vector(block: &Block<'_>) -> Option<Vec<f32>> {
    let output = <EmbeddingsProcessor as GraphProcessor>::block(block)?;
    embedding_vector(output)
}

fn function_vector(function: &Function<'_>) -> Option<Vec<f32>> {
    let output = <EmbeddingsProcessor as GraphProcessor>::function(function)?;
    embedding_vector(output)
}

fn object_id_for_value(collection: Collection, value: &Value) -> String {
    format!(
        "{}:{}",
        collection.as_str(),
        digest_hex(value.to_string().as_bytes())
    )
}

fn instruction_canonical_value(instruction: &Instruction) -> Result<Value, Error> {
    let mut value = serde_json::to_value(instruction.process_base())
        .map_err(|error| Error::Serialization(error.to_string()))?;
    normalize_instruction_value(&mut value);
    Ok(value)
}

fn block_canonical_value(block: &Block<'_>) -> Result<Value, Error> {
    let mut value = serde_json::to_value(block.process_base())
        .map_err(|error| Error::Serialization(error.to_string()))?;
    normalize_block_value(&mut value);
    Ok(value)
}

fn function_canonical_value(function: &Function<'_>) -> Result<Value, Error> {
    let mut value = serde_json::to_value(function.process_base())
        .map_err(|error| Error::Serialization(error.to_string()))?;
    normalize_function_value(&mut value);
    Ok(value)
}

fn normalize_instruction_value(value: &mut Value) {
    let Some(map) = value.as_object_mut() else {
        return;
    };
    map.remove("address");
    map.remove("functions");
    map.remove("blocks");
    map.remove("to");
    map.remove("next");
    map.remove("processors");
    map.remove("attributes");
}

fn normalize_block_value(value: &mut Value) {
    let Some(map) = value.as_object_mut() else {
        return;
    };
    map.remove("address");
    map.remove("next");
    map.remove("to");
    map.remove("functions");
    map.remove("blocks");
    map.remove("instructions");
    map.remove("processors");
    map.remove("attributes");
}

fn normalize_function_value(value: &mut Value) {
    let Some(map) = value.as_object_mut() else {
        return;
    };
    map.remove("address");
    map.remove("functions");
    map.remove("blocks");
    map.remove("processors");
    map.remove("attributes");
}

fn sample_key(sha256: &str) -> String {
    format!("samples/{}.bin", sha256)
}

fn graph_key(corpus: &str, sha256: &str) -> String {
    format!("graphs/{}/{}.json", corpus, sha256)
}

fn index_entry_key(
    corpus: &str,
    collection: Collection,
    architecture: &str,
    object_id: &str,
) -> String {
    format!(
        "index/{}/{}/{}/{}.json",
        corpus,
        collection.as_str(),
        architecture,
        object_id
    )
}
