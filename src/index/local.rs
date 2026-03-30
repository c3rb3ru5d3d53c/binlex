use crate::Config;
use crate::controlflow::{Block, Function, Graph, GraphSnapshot, Instruction};
use crate::databases::lancedb;
use crate::formats::SymbolJson;
use crate::index::Collection;
use crate::index::Entity;
use crate::math::similarity::cosine;
use crate::metadata::Attribute;
use crate::metadata::SymbolType;
use crate::processor::ProcessorTarget;
use crate::search::{
    Query, QueryCollection, QueryExpr, QueryField, QueryTerm, SearchRoot, query_date_matches,
    query_size_matches,
};
use crate::storage::object_store;
use chrono::{DateTime, SecondsFormat, TimeZone, Utc};
use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct LocalIndex {
    config: Config,
    object_store: object_store::ObjectStore,
    lancedb: lancedb::LanceDB,
    pending: Arc<Mutex<PendingBatch>>,
}

#[derive(Debug)]
pub enum Error {
    InvalidConfiguration(&'static str),
    Validation(String),
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
            Self::ObjectStore(message) => write!(f, "local index object store error: {}", message),
            Self::LanceDb(message) => write!(f, "local index lancedb error: {}", message),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Serialize, Deserialize)]
struct StoredGraphRecord {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    attributes: Option<Value>,
    snapshot: GraphSnapshot,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct CorpusEntry {
    corpus: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    attributes: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct IndexEntry {
    object_id: String,
    entity: Collection,
    architecture: String,
    sha256: String,
    address: u64,
    size: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    indexed_at: String,
    vector: Vec<f32>,
    corpora: Vec<CorpusEntry>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct SampleMembership {
    corpora: Vec<String>,
}

#[derive(Clone, Default)]
struct PendingBatch {
    graphs: BTreeMap<String, StoredGraphRecord>,
    entries: BTreeMap<String, IndexEntry>,
    sample_memberships: BTreeMap<String, SampleMembership>,
    deleted_samples: Vec<(String, String)>,
    deleted_corpora: Vec<String>,
}

const DEFAULT_INDEX_GRAPH_COLLECTIONS: &[Collection] = &[Collection::Block, Collection::Function];

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SearchResult {
    corpus: String,
    object_id: String,
    entity: Collection,
    architecture: String,
    sha256: String,
    address: u64,
    size: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    indexed_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    symbol: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    attributes: Vec<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    vector: Vec<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    json: Option<Value>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    embedding: String,
    #[serde(default)]
    embeddings: u64,
    score: f32,
}

impl SearchResult {
    pub fn corpus(&self) -> &str {
        &self.corpus
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

    pub fn date(&self) -> DateTime<Utc> {
        parse_indexed_at(&self.indexed_at)
            .unwrap_or_else(|| Utc.timestamp_opt(0, 0).single().expect("unix epoch is valid"))
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

impl LocalIndex {
    pub fn new(config: Config) -> Result<Self, Error> {
        Self::with_options(config, None, None)
    }

    pub fn with_options(
        config: Config,
        directory: Option<PathBuf>,
        dimensions: Option<usize>,
    ) -> Result<Self, Error> {
        let root = resolve_root(directory, &config)?;
        let mut config = config;
        if let Some(dimensions) = dimensions {
            config.index.local.dimensions = Some(dimensions);
        }
        let object_store = object_store::ObjectStore::new(root.join("object_store"))
            .map_err(|error| Error::ObjectStore(error.to_string()))?;
        let lancedb = lancedb::LanceDB::new(root.join("lancedb"))
            .map_err(|error| Error::LanceDb(error.to_string()))?;
        let index = Self {
            config,
            object_store,
            lancedb,
            pending: Arc::new(Mutex::new(PendingBatch::default())),
        };
        index.validate_configuration()?;
        Ok(index)
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    fn validate_configuration(&self) -> Result<(), Error> {
        if let Some(dimensions) = self.config.index.local.dimensions {
            if dimensions == 0 {
                return Err(Error::InvalidConfiguration(
                    "index.local.dimensions must be greater than zero",
                ));
            }
        }
        self.validate_existing_table_dimensions()
    }

    fn validate_existing_table_dimensions(&self) -> Result<(), Error> {
        let Some(expected_dimensions) = self.config.index.local.dimensions else {
            return Ok(());
        };
        for table_name in self
            .lancedb
            .table_names()
            .map_err(|error| Error::LanceDb(error.to_string()))?
        {
            let Some(actual_dimensions) = self
                .lancedb
                .table_dimensions_by_name(&table_name)
                .map_err(|error| Error::LanceDb(error.to_string()))?
            else {
                continue;
            };
            if actual_dimensions != expected_dimensions {
                return Err(Error::Validation(format!(
                    "existing local index table {} uses dimensions {}, but index.local.dimensions is {}",
                    table_name, actual_dimensions, expected_dimensions
                )));
            }
        }
        Ok(())
    }

    fn validate_vector_dimensions(&self, vector: &[f32]) -> Result<(), Error> {
        if let Some(expected_dimensions) = self.config.index.local.dimensions {
            if vector.len() != expected_dimensions {
                return Err(Error::Validation(format!(
                    "vector length {} does not match configured index.local.dimensions {}",
                    vector.len(),
                    expected_dimensions
                )));
            }
        }
        Ok(())
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

    pub fn graph(
        &self,
        corpus: &str,
        sha256: &str,
        graph: &Graph,
        attributes: &[Attribute],
        selector: Option<&str>,
        collections: Option<&[Collection]>,
    ) -> Result<(), Error> {
        self.graph_many(
            &[corpus.to_string()],
            sha256,
            graph,
            attributes,
            selector,
            collections,
        )
    }

    pub fn graph_many(
        &self,
        corpora: &[String],
        sha256: &str,
        graph: &Graph,
        attributes: &[Attribute],
        selector: Option<&str>,
        collections: Option<&[Collection]>,
    ) -> Result<(), Error> {
        self.stage_graph_json_attributes(
            corpora,
            sha256,
            graph,
            process_attributes(attributes),
            attributes,
            selector,
            collections,
        )
    }

    pub fn instruction(
        &self,
        corpora: &[String],
        instruction: &Instruction,
        vector: &[f32],
        sha256: &str,
        attributes: &[Attribute],
    ) -> Result<(), Error> {
        self.index_many(
            corpora,
            Entity::Instruction,
            instruction.architecture,
            vector,
            sha256,
            instruction.address,
            instruction.size() as u64,
            attributes,
        )
    }

    pub fn block(
        &self,
        corpora: &[String],
        block: &Block,
        vector: &[f32],
        sha256: &str,
        attributes: &[Attribute],
    ) -> Result<(), Error> {
        self.index_many(
            corpora,
            Entity::Block,
            block.cfg.architecture,
            vector,
            sha256,
            block.address,
            block.size() as u64,
            attributes,
        )
    }

    pub fn function(
        &self,
        corpora: &[String],
        function: &Function,
        vector: &[f32],
        sha256: &str,
        attributes: &[Attribute],
    ) -> Result<(), Error> {
        self.index_many(
            corpora,
            Entity::Function,
            function.cfg.architecture,
            vector,
            sha256,
            function.address,
            function.size() as u64,
            attributes,
        )
    }

    fn index_many(
        &self,
        corpora: &[String],
        collection: Collection,
        architecture: crate::Architecture,
        vector: &[f32],
        sha256: &str,
        address: u64,
        size: u64,
        attributes: &[Attribute],
    ) -> Result<(), Error> {
        if vector.is_empty() {
            return Err(Error::InvalidConfiguration("vector must not be empty"));
        }
        self.validate_vector_dimensions(vector)?;
        if sha256.trim().is_empty() {
            return Err(Error::InvalidConfiguration("sha256 must not be empty"));
        }
        let corpora = normalize_corpora(corpora)?;
        let object_id = manual_object_id(collection, &architecture.to_string(), sha256, address);
        let attributes = attributes
            .iter()
            .map(Attribute::to_json_value)
            .collect::<Vec<_>>();
        let mut pending = self.pending.lock().unwrap();
        accumulate_sample_membership(&mut pending.sample_memberships, sha256, &corpora);
        accumulate_entry(
            &mut pending.entries,
            index_entry_key(collection, &architecture.to_string(), &object_id),
            collection,
            &architecture.to_string(),
            object_id,
            sha256,
            address,
            size,
            vector.to_vec(),
            &corpora,
            &attributes,
        );
        Ok(())
    }

    pub fn commit(&self) -> Result<(), Error> {
        let pending = self.pending.lock().unwrap().clone();
        for corpus in unique_corpora(&pending.deleted_corpora) {
            self.delete_corpus_committed(&corpus)?;
        }
        for (corpus, sha256) in unique_samples(&pending.deleted_samples) {
            self.delete_sample_committed(&corpus, &sha256)?;
        }
        for (key, record) in &pending.graphs {
            self.object_store
                .put_json(key, record)
                .map_err(|error| Error::ObjectStore(error.to_string()))?;
        }
        for (key, staged) in &pending.sample_memberships {
            let mut membership = match self.object_store.get_json::<SampleMembership>(key) {
                Ok(existing) => existing,
                Err(object_store::Error::NotFound(_)) => SampleMembership::default(),
                Err(error) => return Err(Error::ObjectStore(error.to_string())),
            };
            membership.corpora = union_corpora(&membership.corpora, &staged.corpora);
            self.object_store
                .put_json(key, &membership)
                .map_err(|error| Error::ObjectStore(error.to_string()))?;
        }
        let mut grouped_rows = BTreeMap::<(Entity, String), Vec<lancedb::Row>>::new();
        for (key, staged) in &pending.entries {
            let mut entry = match self.object_store.get_json::<IndexEntry>(key) {
                Ok(existing) => existing,
                Err(object_store::Error::NotFound(_)) => IndexEntry {
                    object_id: staged.object_id.clone(),
                    entity: staged.entity,
                    architecture: staged.architecture.clone(),
                    sha256: staged.sha256.clone(),
                    address: staged.address,
                    size: staged.size,
                    indexed_at: staged.indexed_at.clone(),
                    vector: staged.vector.clone(),
                    corpora: Vec::new(),
                },
                Err(error) => return Err(Error::ObjectStore(error.to_string())),
            };
            for corpus_entry in &staged.corpora {
                merge_corpus_entry(&mut entry.corpora, corpus_entry);
            }
            entry.sha256 = staged.sha256.clone();
            entry.address = staged.address;
            entry.size = staged.size;
            entry.indexed_at = staged.indexed_at.clone();
            entry.vector = staged.vector.clone();
            self.object_store
                .put_json(key, &entry)
                .map_err(|error| Error::ObjectStore(error.to_string()))?;
            let occurrences_json = serde_json::to_string(&entry.corpora)
                .map_err(|error| Error::Serialization(error.to_string()))?;
            grouped_rows
                .entry((entry.entity, entry.architecture.clone()))
                .or_default()
                .push(lancedb::Row {
                    object_id: entry.object_id.clone(),
                    sha256: Some(entry.sha256.clone()),
                    address: Some(entry.address),
                    occurrences_json,
                    vector: entry.vector.clone(),
                });
        }
        for ((collection, architecture), rows) in grouped_rows {
            self.lancedb
                .upsert_rows(collection, &architecture, &rows)
                .map_err(|error| Error::LanceDb(error.to_string()))?;
        }
        self.clear();
        Ok(())
    }

    pub fn clear(&self) {
        let mut pending = self.pending.lock().unwrap();
        pending.graphs.clear();
        pending.entries.clear();
        pending.sample_memberships.clear();
        pending.deleted_samples.clear();
        pending.deleted_corpora.clear();
    }

    fn stage_graph_json_attributes(
        &self,
        corpora: &[String],
        sha256: &str,
        graph: &Graph,
        attributes: Option<Value>,
        entity_attributes: &[Attribute],
        selector: Option<&str>,
        collections: Option<&[Collection]>,
    ) -> Result<(), Error> {
        if sha256.trim().is_empty() {
            return Err(Error::InvalidConfiguration("sha256 must not be empty"));
        }
        let corpora = normalize_corpora(corpora)?;
        let record = StoredGraphRecord {
            attributes,
            snapshot: graph.snapshot(),
        };
        let mut pending = self.pending.lock().unwrap();
        pending.graphs.insert(graph_key(sha256), record);
        accumulate_sample_membership(&mut pending.sample_memberships, sha256, &corpora);
        if let Some(selector) = selector {
            if selector.trim().is_empty() {
                return Err(Error::InvalidConfiguration("selector must not be empty"));
            }
            self.stage_graph_selected_vectors(
                &mut pending.entries,
                &corpora,
                sha256,
                graph,
                entity_attributes,
                selector,
                collections,
            )?;
        }
        Ok(())
    }

    pub fn load(&self, corpus: &str, sha256: &str) -> Result<Graph, Error> {
        validate_corpus_sha256(corpus, sha256)?;
        if !self.sample_has_corpus(sha256, corpus)? {
            return Err(Error::NotFound(format!("graph {}/{}", corpus, sha256)));
        }
        let record: StoredGraphRecord =
            self.object_store
                .get_json(&graph_key(sha256))
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
        corpora: &[String],
        vector: &[f32],
        collections: Option<&[Collection]>,
        architectures: &[crate::Architecture],
        limit: usize,
    ) -> Result<Vec<SearchResult>, Error> {
        self.search_page(corpora, vector, collections, architectures, 0, limit)
    }

    pub fn search_page(
        &self,
        corpora: &[String],
        vector: &[f32],
        collections: Option<&[Collection]>,
        architectures: &[crate::Architecture],
        offset: usize,
        limit: usize,
    ) -> Result<Vec<SearchResult>, Error> {
        if corpora.is_empty() {
            return Err(Error::InvalidConfiguration("corpora must not be empty"));
        }
        if vector.is_empty() {
            return Err(Error::InvalidConfiguration("vector must not be empty"));
        }
        self.validate_vector_dimensions(vector)?;
        let collections = collections.unwrap_or(DEFAULT_INDEX_GRAPH_COLLECTIONS);
        if collections.is_empty() {
            return Err(Error::InvalidConfiguration("collections must not be empty"));
        }
        let corpora = normalize_corpora(corpora)?;
        let requested_corpora = corpora.iter().cloned().collect::<BTreeSet<_>>();
        let mut hits = Vec::new();
        let mut graph_cache = BTreeMap::<(String, String), Graph>::new();
        let mut collections = collections.to_vec();
        collections.sort();
        collections.dedup();
        for entity in &collections {
            let target_architectures = if architectures.is_empty() {
                self.entity_architectures(*entity)?
            } else {
                architectures
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            };
            for architecture in target_architectures {
                let rows = match self
                    .lancedb
                    .search(*entity, &architecture, vector, offset.saturating_add(limit))
                {
                    Ok(rows) => rows,
                    Err(error) if error.to_string().contains("not found") => continue,
                    Err(error) => return Err(Error::LanceDb(error.to_string())),
                };
                for row in rows {
                    let corpus_entries: Vec<CorpusEntry> =
                        serde_json::from_str(&row.occurrences_json)
                            .map_err(|error| Error::Serialization(error.to_string()))?;
                    let score = cosine(vector, &row.vector);
                    let entry = self
                        .object_store
                        .get_json::<IndexEntry>(&index_entry_key(*entity, &architecture, &row.object_id))
                        .map_err(|error| Error::ObjectStore(error.to_string()))?;
                    let (sha256, address) = match (row.sha256.as_deref(), row.address) {
                        (Some(sha256), Some(address)) => (sha256.to_string(), address),
                        _ => (entry.sha256.clone(), entry.address),
                    };
                    for corpus_entry in corpus_entries
                        .iter()
                        .filter(|corpus_entry| requested_corpora.contains(&corpus_entry.corpus))
                    {
                        let symbols =
                            symbol_names_for_attributes(&corpus_entry.attributes, *entity, address);
                        if symbols.is_empty() {
                            hits.push(SearchResult {
                                corpus: corpus_entry.corpus.clone(),
                                object_id: row.object_id.clone(),
                                entity: *entity,
                                architecture: architecture.clone(),
                                sha256: sha256.clone(),
                                address,
                                size: entry.size,
                                indexed_at: entry.indexed_at.clone(),
                                symbol: None,
                                attributes: corpus_entry.attributes.clone(),
                                vector: row.vector.clone(),
                                json: entity_json_for_result(
                                    self,
                                    &mut graph_cache,
                                    &corpus_entry.corpus,
                                    &sha256,
                                    *entity,
                                    address,
                                ),
                                embedding: String::new(),
                                embeddings: 0,
                                score,
                            });
                            continue;
                        }
                        for symbol in symbols {
                            hits.push(SearchResult {
                                corpus: corpus_entry.corpus.clone(),
                                object_id: row.object_id.clone(),
                                entity: *entity,
                                architecture: architecture.clone(),
                                sha256: sha256.clone(),
                                address,
                                size: entry.size,
                                indexed_at: entry.indexed_at.clone(),
                                symbol: Some(symbol),
                                attributes: corpus_entry.attributes.clone(),
                                vector: row.vector.clone(),
                                json: entity_json_for_result(
                                    self,
                                    &mut graph_cache,
                                    &corpus_entry.corpus,
                                    &sha256,
                                    *entity,
                                    address,
                                ),
                                embedding: String::new(),
                                embeddings: 0,
                                score,
                            });
                        }
                    }
                }
            }
        }
        hits.sort_by(|lhs, rhs| rhs.score.total_cmp(&lhs.score));
        self.attach_embedding_metadata(page_search_results(hits, offset, limit))
    }

    pub fn corpora(&self) -> Result<Vec<String>, Error> {
        let memberships = self
            .object_store
            .list_json_prefix::<SampleMembership>("memberships/samples/")
            .map_err(|error| Error::ObjectStore(error.to_string()))?;
        Ok(unique_corpora(
            &memberships
                .into_iter()
                .flat_map(|membership| membership.corpora)
                .collect::<Vec<_>>(),
        ))
    }

    pub fn search_corpora(&self, query: &str, limit: usize) -> Result<Vec<String>, Error> {
        let mut corpora = self.corpora()?;
        let query = query.trim().to_ascii_lowercase();
        if query.is_empty() {
            if corpora.len() > limit {
                corpora.truncate(limit);
            }
            return Ok(corpora);
        }
        corpora.sort_by(|lhs, rhs| {
            corpus_match_score(lhs, &query)
                .cmp(&corpus_match_score(rhs, &query))
                .then_with(|| lhs.cmp(rhs))
        });
        corpora.reverse();
        corpora.retain(|corpus| corpus_match_score(corpus, &query) > 0);
        if corpora.len() > limit {
            corpora.truncate(limit);
        }
        Ok(corpora)
    }

    pub fn query(&self, query: &str, top_k: usize, page: usize) -> Result<Vec<SearchResult>, Error> {
        let top_k = top_k.max(1);
        let page = page.max(1);
        let offset = page.saturating_sub(1).saturating_mul(top_k);
        let broad_limit = offset
            .saturating_add(top_k.saturating_mul(8))
            .saturating_add(1)
            .clamp(64, 512);
        let query = Query::parse(query).map_err(|error| Error::Validation(error.to_string()))?;
        let analysis = query
            .analyze()
            .map_err(|error| Error::Validation(error.to_string()))?;
        let corpora = resolve_query_corpora(self, &analysis.corpora)?;
        let collections = if analysis.collections.is_empty() {
            DEFAULT_INDEX_GRAPH_COLLECTIONS.to_vec()
        } else {
            analysis
                .collections
                .iter()
                .copied()
                .map(map_query_collection)
                .collect::<Vec<_>>()
        };
        let mut candidates = match &analysis.root {
            Some(SearchRoot::Sha256(sha256)) => self.exact_search_page(
                &corpora,
                sha256,
                Some(&collections),
                &analysis.architectures,
                0,
                broad_limit,
            )?,
            Some(SearchRoot::Embedding(embedding)) => self.embedding_search_page(
                &corpora,
                embedding,
                Some(&collections),
                &analysis.architectures,
                0,
                broad_limit,
            )?,
            Some(SearchRoot::Vector(vector)) => self.search_page(
                &corpora,
                vector,
                Some(&collections),
                &analysis.architectures,
                0,
                broad_limit,
            )?,
            None => self.scan_search_page(
                &corpora,
                Some(&collections),
                &analysis.architectures,
                0,
                broad_limit,
            )?,
        };
        candidates.retain(|result| search_expr_matches(result, query.expr(), &analysis.root));
        candidates.sort_by(|lhs, rhs| rhs.score().total_cmp(&lhs.score()));
        Ok(candidates.into_iter().skip(offset).take(top_k).collect())
    }

    pub fn add_symbol(&self, sha256: &str, address: u64, name: &str) -> Result<(), Error> {
        self.mutate_symbol(sha256, address, name, SymbolMutation::Add)
    }

    pub fn remove_symbol(&self, sha256: &str, address: u64, name: &str) -> Result<(), Error> {
        self.mutate_symbol(sha256, address, name, SymbolMutation::Remove)
    }

    pub fn replace_symbol(&self, sha256: &str, address: u64, name: &str) -> Result<(), Error> {
        self.mutate_symbol(sha256, address, name, SymbolMutation::Replace)
    }

    pub fn add_corpus(&self, sha256: &str, corpus: &str) -> Result<(), Error> {
        self.mutate_corpus_membership(sha256, corpus, CorpusMutation::Add)
    }

    pub fn replace_corpus(&self, sha256: &str, corpus: &str) -> Result<(), Error> {
        self.mutate_corpus_membership(sha256, corpus, CorpusMutation::Replace)
    }

    pub fn rename_corpus(&self, old_name: &str, new_name: &str) -> Result<(), Error> {
        let old_name = old_name.trim();
        let new_name = new_name.trim();
        if old_name.is_empty() || new_name.is_empty() {
            return Err(Error::Validation("corpus must not be empty".to_string()));
        }
        if old_name == new_name {
            return Ok(());
        }

        let membership_keys = self
            .object_store
            .list_prefix("memberships/samples/")
            .map_err(|error| Error::ObjectStore(error.to_string()))?;
        for key in membership_keys {
            let mut membership = self
                .object_store
                .get_json::<SampleMembership>(&key)
                .map_err(|error| Error::ObjectStore(error.to_string()))?;
            let before = membership.corpora.clone();
            membership.corpora = membership
                .corpora
                .iter()
                .map(|corpus| {
                    if corpus == old_name {
                        new_name.to_string()
                    } else {
                        corpus.clone()
                    }
                })
                .collect::<Vec<_>>();
            membership.corpora = unique_corpora(&membership.corpora);
            if membership.corpora != before {
                self.object_store
                    .put_json(&key, &membership)
                    .map_err(|error| Error::ObjectStore(error.to_string()))?;
            }
        }

        let keys = self
            .object_store
            .list_prefix("index/")
            .map_err(|error| Error::ObjectStore(error.to_string()))?;
        let mut updated_rows = BTreeMap::<(Entity, String), Vec<lancedb::Row>>::new();
        for key in keys {
            let mut entry = self
                .object_store
                .get_json::<IndexEntry>(&key)
                .map_err(|error| Error::ObjectStore(error.to_string()))?;
            let mut changed = false;
            for corpus_entry in &mut entry.corpora {
                if corpus_entry.corpus == old_name {
                    corpus_entry.corpus = new_name.to_string();
                    changed = true;
                }
            }
            if !changed {
                continue;
            }
            dedupe_corpus_entries(&mut entry.corpora);
            self.object_store
                .put_json(&key, &entry)
                .map_err(|error| Error::ObjectStore(error.to_string()))?;
            updated_rows
                .entry((entry.entity, entry.architecture.clone()))
                .or_default()
                .push(lancedb::Row {
                    object_id: entry.object_id.clone(),
                    sha256: Some(entry.sha256.clone()),
                    address: Some(entry.address),
                    occurrences_json: serde_json::to_string(&entry.corpora)
                        .map_err(|error| Error::Serialization(error.to_string()))?,
                    vector: entry.vector.clone(),
                });
        }
        for ((collection, architecture), rows) in updated_rows {
            self.lancedb
                .upsert_rows(collection, &architecture, &rows)
                .map_err(|error| Error::LanceDb(error.to_string()))?;
        }
        Ok(())
    }

    pub fn architectures(&self) -> Result<Vec<String>, Error> {
        let keys = self
            .object_store
            .list_prefix("index/")
            .map_err(|error| Error::ObjectStore(error.to_string()))?;
        let mut architectures = keys
            .into_iter()
            .filter_map(|key| architecture_from_index_entry_key(&key))
            .collect::<Vec<_>>();
        architectures.sort();
        architectures.dedup();
        Ok(architectures)
    }

    fn mutate_symbol(
        &self,
        sha256: &str,
        address: u64,
        name: &str,
        mutation: SymbolMutation,
    ) -> Result<(), Error> {
        let sha256 = sha256.trim();
        if !is_sha256(sha256) {
            return Err(Error::Validation(format!("invalid sha256 {}", sha256)));
        }
        let name = name.trim();
        if name.is_empty() {
            return Err(Error::Validation("symbol name must not be empty".to_string()));
        }
        if !self
            .object_store
            .exists(&sample_key(sha256))
            .map_err(|error| Error::ObjectStore(error.to_string()))?
        {
            return Err(Error::NotFound(format!("sample {}", sha256)));
        }

        let keys = self
            .object_store
            .list_prefix("index/")
            .map_err(|error| Error::ObjectStore(error.to_string()))?;
        let mut updated_rows = BTreeMap::<(Entity, String), Vec<lancedb::Row>>::new();
        let mut matched_entry = false;
        let mut matched_symbol = false;
        for key in keys {
            let mut entry = self
                .object_store
                .get_json::<IndexEntry>(&key)
                .map_err(|error| Error::ObjectStore(error.to_string()))?;
            if entry.sha256 != sha256 || entry.address != address {
                continue;
            }
            matched_entry = true;
            let mut changed = false;
            for corpus_entry in &mut entry.corpora {
                let (corpus_changed, corpus_matched_symbol) = mutate_symbol_attributes(
                    &mut corpus_entry.attributes,
                    entry.entity,
                    address,
                    name,
                    mutation,
                );
                changed |= corpus_changed;
                matched_symbol |= corpus_matched_symbol;
            }
            if !changed {
                continue;
            }
            self.object_store
                .put_json(&key, &entry)
                .map_err(|error| Error::ObjectStore(error.to_string()))?;
            updated_rows
                .entry((entry.entity, entry.architecture.clone()))
                .or_default()
                .push(lancedb::Row {
                    object_id: entry.object_id.clone(),
                    sha256: Some(entry.sha256.clone()),
                    address: Some(entry.address),
                    occurrences_json: serde_json::to_string(&entry.corpora)
                        .map_err(|error| Error::Serialization(error.to_string()))?,
                    vector: entry.vector.clone(),
                });
        }

        if !matched_entry {
            return Err(Error::NotFound(format!(
                "indexed address {:#x} for sample {}",
                address, sha256
            )));
        }
        if matches!(mutation, SymbolMutation::Remove) && !matched_symbol {
            return Err(Error::NotFound(format!(
                "symbol {} at address {:#x} for sample {}",
                name, address, sha256
            )));
        }

        for ((collection, architecture), rows) in updated_rows {
            self.lancedb
                .upsert_rows(collection, &architecture, &rows)
                .map_err(|error| Error::LanceDb(error.to_string()))?;
        }
        Ok(())
    }

    fn mutate_corpus_membership(
        &self,
        sha256: &str,
        corpus: &str,
        mutation: CorpusMutation,
    ) -> Result<(), Error> {
        let sha256 = sha256.trim();
        if !is_sha256(sha256) {
            return Err(Error::Validation(format!("invalid sha256 {}", sha256)));
        }
        let corpus = corpus.trim();
        if corpus.is_empty() {
            return Err(Error::Validation("corpus must not be empty".to_string()));
        }
        if !self
            .object_store
            .exists(&sample_key(sha256))
            .map_err(|error| Error::ObjectStore(error.to_string()))?
        {
            return Err(Error::NotFound(format!("sample {}", sha256)));
        }

        let membership_key = sample_membership_key(sha256);
        let mut membership = self
            .object_store
            .get_json::<SampleMembership>(&membership_key)
            .map_err(|error| match error {
                object_store::Error::NotFound(_) => {
                    Error::NotFound(format!("sample membership {}", sha256))
                }
                other => Error::ObjectStore(other.to_string()),
            })?;
        membership.corpora = match mutation {
            CorpusMutation::Add => union_corpora(&membership.corpora, &[corpus.to_string()]),
            CorpusMutation::Replace => vec![corpus.to_string()],
        };
        self.object_store
            .put_json(&membership_key, &membership)
            .map_err(|error| Error::ObjectStore(error.to_string()))?;

        let keys = self
            .object_store
            .list_prefix("index/")
            .map_err(|error| Error::ObjectStore(error.to_string()))?;
        let mut updated_rows = BTreeMap::<(Entity, String), Vec<lancedb::Row>>::new();
        let mut matched_entry = false;
        for key in keys {
            let mut entry = self
                .object_store
                .get_json::<IndexEntry>(&key)
                .map_err(|error| Error::ObjectStore(error.to_string()))?;
            if entry.sha256 != sha256 {
                continue;
            }
            matched_entry = true;
            let template_attributes = entry
                .corpora
                .first()
                .map(|corpus_entry| corpus_entry.attributes.clone())
                .unwrap_or_default();
            entry.corpora = match mutation {
                CorpusMutation::Add => {
                    let mut corpora_entries = entry.corpora.clone();
                    merge_corpus_entry(
                        &mut corpora_entries,
                        &CorpusEntry {
                            corpus: corpus.to_string(),
                            attributes: template_attributes.clone(),
                        },
                    );
                    corpora_entries
                }
                CorpusMutation::Replace => vec![CorpusEntry {
                    corpus: corpus.to_string(),
                    attributes: template_attributes.clone(),
                }],
            };
            dedupe_corpus_entries(&mut entry.corpora);
            self.object_store
                .put_json(&key, &entry)
                .map_err(|error| Error::ObjectStore(error.to_string()))?;
            updated_rows
                .entry((entry.entity, entry.architecture.clone()))
                .or_default()
                .push(lancedb::Row {
                    object_id: entry.object_id.clone(),
                    sha256: Some(entry.sha256.clone()),
                    address: Some(entry.address),
                    occurrences_json: serde_json::to_string(&entry.corpora)
                        .map_err(|error| Error::Serialization(error.to_string()))?,
                    vector: entry.vector.clone(),
                });
        }
        if !matched_entry {
            return Err(Error::NotFound(format!("indexed sample {}", sha256)));
        }
        for ((collection, architecture), rows) in updated_rows {
            self.lancedb
                .upsert_rows(collection, &architecture, &rows)
                .map_err(|error| Error::LanceDb(error.to_string()))?;
        }
        Ok(())
    }

    pub fn exact_search(
        &self,
        corpora: &[String],
        sha256: &str,
        collections: Option<&[Collection]>,
        architectures: &[crate::Architecture],
        limit: usize,
    ) -> Result<Vec<SearchResult>, Error> {
        self.exact_search_page(corpora, sha256, collections, architectures, 0, limit)
    }

    pub fn exact_search_page(
        &self,
        corpora: &[String],
        sha256: &str,
        collections: Option<&[Collection]>,
        architectures: &[crate::Architecture],
        offset: usize,
        limit: usize,
    ) -> Result<Vec<SearchResult>, Error> {
        if corpora.is_empty() {
            return Err(Error::InvalidConfiguration("corpora must not be empty"));
        }
        if sha256.trim().is_empty() {
            return Err(Error::InvalidConfiguration("sha256 must not be empty"));
        }
        let collections = collections.unwrap_or(DEFAULT_INDEX_GRAPH_COLLECTIONS);
        if collections.is_empty() {
            return Err(Error::InvalidConfiguration("collections must not be empty"));
        }
        let corpora = normalize_corpora(corpora)?;
        let requested_corpora = corpora.iter().cloned().collect::<BTreeSet<_>>();
        let requested_architectures = architectures
            .iter()
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>();
        let requested_collections = collections.iter().copied().collect::<BTreeSet<_>>();
        let keys = self
            .object_store
            .list_prefix("index/")
            .map_err(|error| Error::ObjectStore(error.to_string()))?;
        let mut hits = Vec::new();
        let mut graph_cache = BTreeMap::<(String, String), Graph>::new();
        for key in keys {
            let entry = self
                .object_store
                .get_json::<IndexEntry>(&key)
                .map_err(|error| Error::ObjectStore(error.to_string()))?;
            if entry.sha256 != sha256 {
                continue;
            }
            if !requested_collections.contains(&entry.entity) {
                continue;
            }
            if !requested_architectures.is_empty()
                && !requested_architectures.contains(&entry.architecture)
            {
                continue;
            }
            for corpus_entry in entry
                .corpora
                .iter()
                .filter(|corpus_entry| requested_corpora.contains(&corpus_entry.corpus))
            {
                let symbols = symbol_names_for_attributes(
                    &corpus_entry.attributes,
                    entry.entity,
                    entry.address,
                );
                if symbols.is_empty() {
                    hits.push(SearchResult {
                        corpus: corpus_entry.corpus.clone(),
                        object_id: entry.object_id.clone(),
                        entity: entry.entity,
                        architecture: entry.architecture.clone(),
                        sha256: entry.sha256.clone(),
                        address: entry.address,
                        size: entry.size,
                        indexed_at: entry.indexed_at.clone(),
                        symbol: None,
                        attributes: corpus_entry.attributes.clone(),
                        vector: entry.vector.clone(),
                        json: entity_json_for_result(
                            self,
                            &mut graph_cache,
                            &corpus_entry.corpus,
                            &entry.sha256,
                            entry.entity,
                            entry.address,
                        ),
                        embedding: String::new(),
                        embeddings: 0,
                        score: 1.0,
                    });
                    continue;
                }
                for symbol in symbols {
                    hits.push(SearchResult {
                        corpus: corpus_entry.corpus.clone(),
                        object_id: entry.object_id.clone(),
                        entity: entry.entity,
                        architecture: entry.architecture.clone(),
                        sha256: entry.sha256.clone(),
                        address: entry.address,
                        size: entry.size,
                        indexed_at: entry.indexed_at.clone(),
                        symbol: Some(symbol),
                        attributes: corpus_entry.attributes.clone(),
                        vector: entry.vector.clone(),
                        json: entity_json_for_result(
                            self,
                            &mut graph_cache,
                            &corpus_entry.corpus,
                            &entry.sha256,
                            entry.entity,
                            entry.address,
                        ),
                        embedding: String::new(),
                        embeddings: 0,
                        score: 1.0,
                    });
                }
            }
        }
        hits.sort_by(|lhs, rhs| {
            rhs.score
                .total_cmp(&lhs.score)
                .then_with(|| lhs.corpus.cmp(&rhs.corpus))
                .then_with(|| lhs.architecture.cmp(&rhs.architecture))
                .then_with(|| lhs.entity.cmp(&rhs.entity))
                .then_with(|| lhs.address.cmp(&rhs.address))
        });
        self.attach_embedding_metadata(page_search_results(hits, offset, limit))
    }

    pub fn embedding_search(
        &self,
        corpora: &[String],
        embedding: &str,
        collections: Option<&[Collection]>,
        architectures: &[crate::Architecture],
        limit: usize,
    ) -> Result<Vec<SearchResult>, Error> {
        self.embedding_search_page(corpora, embedding, collections, architectures, 0, limit)
    }

    pub fn embedding_search_page(
        &self,
        corpora: &[String],
        embedding: &str,
        collections: Option<&[Collection]>,
        architectures: &[crate::Architecture],
        offset: usize,
        limit: usize,
    ) -> Result<Vec<SearchResult>, Error> {
        if corpora.is_empty() {
            return Err(Error::InvalidConfiguration("corpora must not be empty"));
        }
        let embedding = embedding.trim().to_ascii_lowercase();
        if embedding.is_empty() {
            return Err(Error::InvalidConfiguration("embedding must not be empty"));
        }
        let collections = collections.unwrap_or(DEFAULT_INDEX_GRAPH_COLLECTIONS);
        if collections.is_empty() {
            return Err(Error::InvalidConfiguration("collections must not be empty"));
        }
        let corpora = normalize_corpora(corpora)?;
        let requested_corpora = corpora.iter().cloned().collect::<BTreeSet<_>>();
        let requested_architectures = architectures
            .iter()
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>();
        let requested_collections = collections.iter().copied().collect::<BTreeSet<_>>();
        let keys = self
            .object_store
            .list_prefix("index/")
            .map_err(|error| Error::ObjectStore(error.to_string()))?;
        let mut hits = Vec::new();
        let mut graph_cache = BTreeMap::<(String, String), Graph>::new();
        for key in keys {
            let entry = self
                .object_store
                .get_json::<IndexEntry>(&key)
                .map_err(|error| Error::ObjectStore(error.to_string()))?;
            if !requested_collections.contains(&entry.entity) {
                continue;
            }
            if !requested_architectures.is_empty()
                && !requested_architectures.contains(&entry.architecture)
            {
                continue;
            }
            if embedding_id_for_vector(&entry.vector) != embedding {
                continue;
            }
            for corpus_entry in entry
                .corpora
                .iter()
                .filter(|corpus_entry| requested_corpora.contains(&corpus_entry.corpus))
            {
                let symbols = symbol_names_for_attributes(
                    &corpus_entry.attributes,
                    entry.entity,
                    entry.address,
                );
                if symbols.is_empty() {
                    hits.push(SearchResult {
                        corpus: corpus_entry.corpus.clone(),
                        object_id: entry.object_id.clone(),
                        entity: entry.entity,
                        architecture: entry.architecture.clone(),
                        sha256: entry.sha256.clone(),
                        address: entry.address,
                        size: entry.size,
                        indexed_at: entry.indexed_at.clone(),
                        symbol: None,
                        attributes: corpus_entry.attributes.clone(),
                        vector: entry.vector.clone(),
                        json: entity_json_for_result(
                            self,
                            &mut graph_cache,
                            &corpus_entry.corpus,
                            &entry.sha256,
                            entry.entity,
                            entry.address,
                        ),
                        embedding: String::new(),
                        embeddings: 0,
                        score: 1.0,
                    });
                    continue;
                }
                for symbol in symbols {
                    hits.push(SearchResult {
                        corpus: corpus_entry.corpus.clone(),
                        object_id: entry.object_id.clone(),
                        entity: entry.entity,
                        architecture: entry.architecture.clone(),
                        sha256: entry.sha256.clone(),
                        address: entry.address,
                        size: entry.size,
                        indexed_at: entry.indexed_at.clone(),
                        symbol: Some(symbol),
                        attributes: corpus_entry.attributes.clone(),
                        vector: entry.vector.clone(),
                        json: entity_json_for_result(
                            self,
                            &mut graph_cache,
                            &corpus_entry.corpus,
                            &entry.sha256,
                            entry.entity,
                            entry.address,
                        ),
                        embedding: String::new(),
                        embeddings: 0,
                        score: 1.0,
                    });
                }
            }
        }
        hits.sort_by(|lhs, rhs| {
            rhs.score
                .total_cmp(&lhs.score)
                .then_with(|| lhs.corpus.cmp(&rhs.corpus))
                .then_with(|| lhs.architecture.cmp(&rhs.architecture))
                .then_with(|| lhs.entity.cmp(&rhs.entity))
                .then_with(|| lhs.address.cmp(&rhs.address))
        });
        self.attach_embedding_metadata(page_search_results(hits, offset, limit))
    }

    pub fn scan_search(
        &self,
        corpora: &[String],
        collections: Option<&[Collection]>,
        architectures: &[crate::Architecture],
        limit: usize,
    ) -> Result<Vec<SearchResult>, Error> {
        self.scan_search_page(corpora, collections, architectures, 0, limit)
    }

    pub fn scan_search_page(
        &self,
        corpora: &[String],
        collections: Option<&[Collection]>,
        architectures: &[crate::Architecture],
        offset: usize,
        limit: usize,
    ) -> Result<Vec<SearchResult>, Error> {
        if corpora.is_empty() {
            return Err(Error::InvalidConfiguration("corpora must not be empty"));
        }
        let collections = collections.unwrap_or(DEFAULT_INDEX_GRAPH_COLLECTIONS);
        if collections.is_empty() {
            return Err(Error::InvalidConfiguration("collections must not be empty"));
        }
        let corpora = normalize_corpora(corpora)?;
        let requested_corpora = corpora.iter().cloned().collect::<BTreeSet<_>>();
        let requested_architectures = architectures
            .iter()
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>();
        let requested_collections = collections.iter().copied().collect::<BTreeSet<_>>();
        let keys = self
            .object_store
            .list_prefix("index/")
            .map_err(|error| Error::ObjectStore(error.to_string()))?;
        let mut hits = Vec::new();
        let mut graph_cache = BTreeMap::<(String, String), Graph>::new();
        for key in keys {
            let entry = self
                .object_store
                .get_json::<IndexEntry>(&key)
                .map_err(|error| Error::ObjectStore(error.to_string()))?;
            if !requested_collections.contains(&entry.entity) {
                continue;
            }
            if !requested_architectures.is_empty()
                && !requested_architectures.contains(&entry.architecture)
            {
                continue;
            }
            for corpus_entry in entry
                .corpora
                .iter()
                .filter(|corpus_entry| requested_corpora.contains(&corpus_entry.corpus))
            {
                let symbols = symbol_names_for_attributes(
                    &corpus_entry.attributes,
                    entry.entity,
                    entry.address,
                );
                if symbols.is_empty() {
                    hits.push(SearchResult {
                        corpus: corpus_entry.corpus.clone(),
                        object_id: entry.object_id.clone(),
                        entity: entry.entity,
                        architecture: entry.architecture.clone(),
                        sha256: entry.sha256.clone(),
                        address: entry.address,
                        size: entry.size,
                        indexed_at: entry.indexed_at.clone(),
                        symbol: None,
                        attributes: corpus_entry.attributes.clone(),
                        vector: entry.vector.clone(),
                        json: entity_json_for_result(
                            self,
                            &mut graph_cache,
                            &corpus_entry.corpus,
                            &entry.sha256,
                            entry.entity,
                            entry.address,
                        ),
                        embedding: String::new(),
                        embeddings: 0,
                        score: 1.0,
                    });
                    continue;
                }
                for symbol in symbols {
                    hits.push(SearchResult {
                        corpus: corpus_entry.corpus.clone(),
                        object_id: entry.object_id.clone(),
                        entity: entry.entity,
                        architecture: entry.architecture.clone(),
                        sha256: entry.sha256.clone(),
                        address: entry.address,
                        size: entry.size,
                        indexed_at: entry.indexed_at.clone(),
                        symbol: Some(symbol),
                        attributes: corpus_entry.attributes.clone(),
                        vector: entry.vector.clone(),
                        json: entity_json_for_result(
                            self,
                            &mut graph_cache,
                            &corpus_entry.corpus,
                            &entry.sha256,
                            entry.entity,
                            entry.address,
                        ),
                        embedding: String::new(),
                        embeddings: 0,
                        score: 1.0,
                    });
                }
            }
        }
        hits.sort_by(|lhs, rhs| {
            rhs.score
                .total_cmp(&lhs.score)
                .then_with(|| lhs.corpus.cmp(&rhs.corpus))
                .then_with(|| lhs.architecture.cmp(&rhs.architecture))
                .then_with(|| lhs.entity.cmp(&rhs.entity))
                .then_with(|| lhs.address.cmp(&rhs.address))
        });
        self.attach_embedding_metadata(page_search_results(hits, offset, limit))
    }

    pub fn delete(&self, corpus: &str, sha256: &str) -> Result<(), Error> {
        validate_corpus_sha256(corpus, sha256)?;
        let mut pending = self.pending.lock().unwrap();
        pending
            .deleted_samples
            .push((corpus.to_string(), sha256.to_string()));
        remove_corpus_from_pending_sample(&mut pending.sample_memberships, sha256, corpus);
        prune_pending_entries_for_sample(&mut pending.entries, sha256, corpus);
        Ok(())
    }

    pub fn delete_corpus(&self, corpus: &str) -> Result<(), Error> {
        if corpus.trim().is_empty() {
            return Err(Error::InvalidConfiguration("corpus must not be empty"));
        }
        let mut pending = self.pending.lock().unwrap();
        pending.deleted_corpora.push(corpus.to_string());
        remove_corpus_from_pending_memberships(&mut pending.sample_memberships, corpus);
        prune_pending_entries_for_corpus(&mut pending.entries, corpus);
        pending
            .deleted_samples
            .retain(|(existing_corpus, _)| existing_corpus != corpus);
        Ok(())
    }

    fn stage_graph_selected_vectors(
        &self,
        entries: &mut BTreeMap<String, IndexEntry>,
        corpora: &[String],
        sha256: &str,
        graph: &Graph,
        attributes: &[Attribute],
        selector: &str,
        collections: Option<&[Collection]>,
    ) -> Result<(), Error> {
        let selected = collections.unwrap_or(DEFAULT_INDEX_GRAPH_COLLECTIONS);
        if selected.contains(&Entity::Instruction) {
            self.stage_instructions(entries, corpora, sha256, graph, attributes, selector)?;
        }
        if selected.contains(&Entity::Block) {
            self.stage_blocks(entries, corpora, sha256, graph, attributes, selector)?;
        }
        if selected.contains(&Entity::Function) {
            self.stage_functions(entries, corpora, sha256, graph, attributes, selector)?;
        }
        Ok(())
    }

    fn stage_instructions(
        &self,
        pending_entries: &mut BTreeMap<String, IndexEntry>,
        corpora: &[String],
        sha256: &str,
        graph: &Graph,
        attributes: &[Attribute],
        selector: &str,
    ) -> Result<(), Error> {
        let processor_selector = if let Some((processor_name, output_selector)) =
            processor_selector(selector)
        {
            let missing = graph.instructions().into_iter().any(|instruction| {
                graph
                    .processor_output(
                        ProcessorTarget::Instruction,
                        instruction.address,
                        processor_name,
                    )
                    .is_none()
            });
            if missing {
                graph
                    .process_instructions()
                    .map_err(|error| Error::Graph(error.to_string()))?;
            }
            Some((processor_name, output_selector))
        } else {
            None
        };
        for instruction in graph.instructions() {
            let Some(vector) =
                instruction_selector_vector(graph, &instruction, selector, processor_selector)?
            else {
                continue;
            };
            self.validate_vector_dimensions(&vector)?;
            let object_id = manual_object_id(
                Entity::Instruction,
                &graph.architecture.to_string(),
                sha256,
                instruction.address,
            );
            accumulate_entry(
                pending_entries,
                index_entry_key(
                    Entity::Instruction,
                    &graph.architecture.to_string(),
                    &object_id,
                ),
                Entity::Instruction,
                &graph.architecture.to_string(),
                object_id,
                sha256,
                instruction.address,
                instruction.size() as u64,
                vector,
                corpora,
                &attributes_for_entity_address(
                    attributes,
                    Entity::Instruction,
                    instruction.address,
                ),
            );
        }
        Ok(())
    }

    fn stage_blocks(
        &self,
        pending_entries: &mut BTreeMap<String, IndexEntry>,
        corpora: &[String],
        sha256: &str,
        graph: &Graph,
        attributes: &[Attribute],
        selector: &str,
    ) -> Result<(), Error> {
        let processor_selector = if let Some((processor_name, output_selector)) =
            processor_selector(selector)
        {
            let missing = graph.blocks().into_iter().any(|block| {
                graph
                    .processor_output(ProcessorTarget::Block, block.address(), processor_name)
                    .is_none()
            });
            if missing {
                graph
                    .process_blocks()
                    .map_err(|error| Error::Graph(error.to_string()))?;
            }
            Some((processor_name, output_selector))
        } else {
            None
        };
        for block in graph.blocks() {
            let Some(vector) = block_selector_vector(graph, &block, selector, processor_selector)?
            else {
                continue;
            };
            self.validate_vector_dimensions(&vector)?;
            let object_id = manual_object_id(
                Entity::Block,
                &graph.architecture.to_string(),
                sha256,
                block.address(),
            );
            accumulate_entry(
                pending_entries,
                index_entry_key(Entity::Block, &graph.architecture.to_string(), &object_id),
                Entity::Block,
                &graph.architecture.to_string(),
                object_id,
                sha256,
                block.address(),
                block.size() as u64,
                vector,
                corpora,
                &attributes_for_entity_address(attributes, Entity::Block, block.address()),
            );
        }
        Ok(())
    }

    fn stage_functions(
        &self,
        pending_entries: &mut BTreeMap<String, IndexEntry>,
        corpora: &[String],
        sha256: &str,
        graph: &Graph,
        attributes: &[Attribute],
        selector: &str,
    ) -> Result<(), Error> {
        let processor_selector = if let Some((processor_name, output_selector)) =
            processor_selector(selector)
        {
            let missing = graph.functions().into_iter().any(|function| {
                graph
                    .processor_output(
                        ProcessorTarget::Function,
                        function.address,
                        processor_name,
                    )
                    .is_none()
            });
            if missing {
                graph
                    .process_functions()
                    .map_err(|error| Error::Graph(error.to_string()))?;
            }
            Some((processor_name, output_selector))
        } else {
            None
        };
        for function in graph.functions() {
            let Some(vector) =
                function_selector_vector(graph, &function, selector, processor_selector)?
            else {
                continue;
            };
            self.validate_vector_dimensions(&vector)?;
            let object_id = manual_object_id(
                Entity::Function,
                &graph.architecture.to_string(),
                sha256,
                function.address,
            );
            accumulate_entry(
                pending_entries,
                index_entry_key(
                    Entity::Function,
                    &graph.architecture.to_string(),
                    &object_id,
                ),
                Entity::Function,
                &graph.architecture.to_string(),
                object_id,
                sha256,
                function.address,
                function.size() as u64,
                vector,
                corpora,
                &attributes_for_entity_address(attributes, Entity::Function, function.address),
            );
        }
        Ok(())
    }

    fn entity_architectures(&self, entity: Entity) -> Result<Vec<String>, Error> {
        let prefix = format!("index/{}/", entity.as_str());
        let mut architectures = self
            .object_store
            .list_prefix(&prefix)
            .map_err(|error| Error::ObjectStore(error.to_string()))?
            .into_iter()
            .filter_map(|key| architecture_from_index_entry_key(&key))
            .collect::<Vec<_>>();
        architectures.sort();
        architectures.dedup();
        Ok(architectures)
    }

    fn delete_sample_committed(&self, corpus: &str, sha256: &str) -> Result<(), Error> {
        let keys = self
            .object_store
            .list_prefix("index/")
            .map_err(|error| Error::ObjectStore(error.to_string()))?;
        let mut updated_rows = BTreeMap::<(Entity, String), Vec<lancedb::Row>>::new();
        let mut deleted_rows = BTreeMap::<(Entity, String), Vec<String>>::new();
        for key in keys {
            let mut entry = self
                .object_store
                .get_json::<IndexEntry>(&key)
                .map_err(|error| Error::ObjectStore(error.to_string()))?;
            let changed = remove_corpus_from_entry(&mut entry, sha256, Some(corpus));
            if !changed {
                continue;
            }
            if entry.corpora.is_empty() {
                self.object_store
                    .delete(&key)
                    .map_err(|error| Error::ObjectStore(error.to_string()))?;
                deleted_rows
                    .entry((entry.entity, entry.architecture.clone()))
                    .or_default()
                    .push(entry.object_id.clone());
                continue;
            }
            self.object_store
                .put_json(&key, &entry)
                .map_err(|error| Error::ObjectStore(error.to_string()))?;
            updated_rows
                .entry((entry.entity, entry.architecture.clone()))
                .or_default()
                .push(lancedb::Row {
                    object_id: entry.object_id.clone(),
                    sha256: Some(entry.sha256.clone()),
                    address: Some(entry.address),
                    occurrences_json: serde_json::to_string(&entry.corpora)
                        .map_err(|error| Error::Serialization(error.to_string()))?,
                    vector: entry.vector.clone(),
                });
        }
        for ((collection, architecture), object_ids) in deleted_rows {
            self.lancedb
                .delete_objects(collection, &architecture, &object_ids)
                .map_err(|error| Error::LanceDb(error.to_string()))?;
        }
        for ((collection, architecture), rows) in updated_rows {
            self.lancedb
                .upsert_rows(collection, &architecture, &rows)
                .map_err(|error| Error::LanceDb(error.to_string()))?;
        }
        self.remove_sample_membership(corpus, sha256)?;
        Ok(())
    }

    fn delete_corpus_committed(&self, corpus: &str) -> Result<(), Error> {
        let memberships = self
            .object_store
            .list_prefix("memberships/samples/")
            .map_err(|error| Error::ObjectStore(error.to_string()))?;
        for key in memberships {
            let Some(sha256) = sha256_from_sample_membership_key(&key) else {
                continue;
            };
            self.delete_sample_committed(corpus, &sha256)?;
        }
        Ok(())
    }

    fn sample_has_corpus(&self, sha256: &str, corpus: &str) -> Result<bool, Error> {
        let membership = match self
            .object_store
            .get_json::<SampleMembership>(&sample_membership_key(sha256))
        {
            Ok(membership) => membership,
            Err(object_store::Error::NotFound(_)) => return Ok(false),
            Err(error) => return Err(Error::ObjectStore(error.to_string())),
        };
        Ok(membership.corpora.iter().any(|existing| existing == corpus))
    }

    fn remove_sample_membership(&self, corpus: &str, sha256: &str) -> Result<(), Error> {
        let key = sample_membership_key(sha256);
        let mut membership = match self.object_store.get_json::<SampleMembership>(&key) {
            Ok(membership) => membership,
            Err(object_store::Error::NotFound(_)) => return Ok(()),
            Err(error) => return Err(Error::ObjectStore(error.to_string())),
        };
        membership.corpora.retain(|existing| existing != corpus);
        if membership.corpora.is_empty() {
            if self
                .object_store
                .exists(&graph_key(sha256))
                .map_err(|error| Error::ObjectStore(error.to_string()))?
            {
                self.object_store
                    .delete(&graph_key(sha256))
                    .map_err(|error| Error::ObjectStore(error.to_string()))?;
            }
            if self
                .object_store
                .exists(&sample_key(sha256))
                .map_err(|error| Error::ObjectStore(error.to_string()))?
            {
                self.object_store
                    .delete(&sample_key(sha256))
                    .map_err(|error| Error::ObjectStore(error.to_string()))?;
            }
            self.object_store
                .delete(&key)
                .map_err(|error| Error::ObjectStore(error.to_string()))?;
            return Ok(());
        }
        self.object_store
            .put_json(&key, &membership)
            .map_err(|error| Error::ObjectStore(error.to_string()))
    }

    fn attach_embedding_metadata(
        &self,
        mut hits: Vec<SearchResult>,
    ) -> Result<Vec<SearchResult>, Error> {
        if hits.is_empty() {
            return Ok(hits);
        }
        let needed = hits
            .iter()
            .map(|hit| (hit.entity, hit.architecture.clone()))
            .collect::<BTreeSet<_>>();
        let keys = self
            .object_store
            .list_prefix("index/")
            .map_err(|error| Error::ObjectStore(error.to_string()))?;
        let mut counts = BTreeMap::<(Collection, String, String), u64>::new();
        for key in keys {
            let entry = self
                .object_store
                .get_json::<IndexEntry>(&key)
                .map_err(|error| Error::ObjectStore(error.to_string()))?;
            if !needed.contains(&(entry.entity, entry.architecture.clone())) {
                continue;
            }
            let embedding = embedding_id_for_vector(&entry.vector);
            *counts
                .entry((entry.entity, entry.architecture.clone(), embedding))
                .or_insert(0) += 1;
        }
        for hit in &mut hits {
            let embedding = embedding_id_for_vector(&hit.vector);
            hit.embeddings = *counts
                .get(&(hit.entity, hit.architecture.clone(), embedding.clone()))
                .unwrap_or(&0);
            hit.embedding = embedding;
        }
        Ok(hits)
    }
}

fn resolve_root(directory: Option<PathBuf>, config: &Config) -> Result<PathBuf, Error> {
    let root = match directory {
        Some(directory) => directory,
        None => PathBuf::from(config.index.local.directory.clone()),
    };
    if root.as_os_str().is_empty() {
        return Err(Error::InvalidConfiguration("directory must not be empty"));
    }
    let root = expand_home_directory(root)?;
    let root = if root.is_absolute() {
        root
    } else {
        std::env::current_dir()
            .map_err(|_| Error::InvalidConfiguration("failed to resolve current directory"))?
            .join(root)
    };
    if root.exists() && !root.is_dir() {
        return Err(Error::InvalidConfiguration(
            "directory must reference a directory path",
        ));
    }
    std::fs::create_dir_all(&root).map_err(|error| Error::ObjectStore(error.to_string()))?;
    Ok(root)
}

fn expand_home_directory(path: PathBuf) -> Result<PathBuf, Error> {
    let value = path.to_string_lossy();
    if value == "~" {
        return dirs::home_dir().ok_or(Error::InvalidConfiguration(
            "unable to resolve home directory",
        ));
    }
    if let Some(remainder) = value.strip_prefix("~/") {
        return dirs::home_dir()
            .ok_or(Error::InvalidConfiguration(
                "unable to resolve home directory",
            ))
            .map(|home| home.join(remainder));
    }
    Ok(path)
}

fn accumulate_entry(
    entries: &mut BTreeMap<String, IndexEntry>,
    key: String,
    entity: Entity,
    architecture: &str,
    object_id: String,
    sha256: &str,
    address: u64,
    size: u64,
    vector: Vec<f32>,
    corpora: &[String],
    attributes: &[Value],
) {
    let entry = entries.entry(key).or_insert_with(|| IndexEntry {
        object_id,
        entity,
        architecture: architecture.to_string(),
        sha256: sha256.to_string(),
        address,
        size,
        vector: vector.clone(),
        indexed_at: current_indexed_at(),
        corpora: Vec::new(),
    });
    entry.entity = entity;
    entry.sha256 = sha256.to_string();
    entry.address = address;
    entry.size = size;
    for corpus in corpora {
        merge_corpus_entry(
            &mut entry.corpora,
            &CorpusEntry {
                corpus: corpus.clone(),
                attributes: attributes.to_vec(),
            },
        );
    }
    entry.vector = vector;
}

fn merge_corpus_entry(corpora: &mut Vec<CorpusEntry>, corpus_entry: &CorpusEntry) {
    if let Some(existing) = corpora
        .iter_mut()
        .find(|existing| existing.corpus == corpus_entry.corpus)
    {
        merge_attribute_values(&mut existing.attributes, &corpus_entry.attributes);
        return;
    }
    let mut entry = corpus_entry.clone();
    dedupe_attribute_values(&mut entry.attributes);
    corpora.push(entry);
}

fn dedupe_corpus_entries(corpora: &mut Vec<CorpusEntry>) {
    let mut merged = Vec::<CorpusEntry>::new();
    for corpus_entry in corpora.clone() {
        merge_corpus_entry(&mut merged, &corpus_entry);
    }
    *corpora = merged;
}

fn accumulate_sample_membership(
    memberships: &mut BTreeMap<String, SampleMembership>,
    sha256: &str,
    corpora: &[String],
) {
    let entry = memberships
        .entry(sample_membership_key(sha256))
        .or_default();
    entry.corpora = union_corpora(&entry.corpora, corpora);
}

fn digest_hex(data: &[u8]) -> String {
    crate::hex::encode(digest(&SHA256, data).as_ref())
}

fn page_search_results(
    mut hits: Vec<SearchResult>,
    offset: usize,
    limit: usize,
) -> Vec<SearchResult> {
    if offset >= hits.len() {
        return Vec::new();
    }
    let end = offset.saturating_add(limit).min(hits.len());
    hits.drain(offset..end).collect()
}

fn embedding_id_for_vector(vector: &[f32]) -> String {
    let mut bytes = Vec::with_capacity(vector.len() * std::mem::size_of::<f32>());
    for value in vector {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    digest_hex(&bytes)
}

fn process_attributes(attributes: &[Attribute]) -> Option<Value> {
    if attributes.is_empty() {
        return None;
    }
    Some(Value::Array(
        attributes
            .iter()
            .map(Attribute::to_json_value)
            .collect::<Vec<_>>(),
    ))
}

fn attributes_for_entity_address(
    attributes: &[Attribute],
    entity: Entity,
    address: u64,
) -> Vec<Value> {
    attributes
        .iter()
        .filter_map(|attribute| match attribute {
            Attribute::Symbol(symbol)
                if symbol.address == address
                    && symbol_type_matches_collection(symbol.symbol_type.as_str(), entity) =>
            {
                Some(attribute.to_json_value())
            }
            _ => None,
        })
        .collect()
}

fn symbol_type_matches_collection(symbol_type: &str, collection: Collection) -> bool {
    match collection {
        Collection::Instruction => symbol_type == SymbolType::Instruction.as_str(),
        Collection::Block => symbol_type == SymbolType::Block.as_str(),
        Collection::Function => symbol_type == SymbolType::Function.as_str(),
    }
}

fn validate_corpus_sha256(corpus: &str, sha256: &str) -> Result<(), Error> {
    if corpus.trim().is_empty() {
        return Err(Error::InvalidConfiguration("corpus must not be empty"));
    }
    if sha256.trim().is_empty() {
        return Err(Error::InvalidConfiguration("sha256 must not be empty"));
    }
    Ok(())
}

fn normalize_corpora(corpora: &[String]) -> Result<Vec<String>, Error> {
    let corpora = unique_corpora(
        &corpora
            .iter()
            .map(|corpus| corpus.trim().to_string())
            .collect::<Vec<_>>(),
    );
    if corpora.is_empty() {
        return Err(Error::InvalidConfiguration("corpora must not be empty"));
    }
    if corpora.iter().any(|corpus| corpus.is_empty()) {
        return Err(Error::InvalidConfiguration("corpus must not be empty"));
    }
    Ok(corpora)
}

fn corpus_match_score(corpus: &str, query: &str) -> usize {
    if query.is_empty() {
        return 1;
    }
    let corpus = corpus.to_ascii_lowercase();
    if corpus == query {
        return 10_000;
    }
    if corpus.starts_with(query) {
        return 8_000usize.saturating_sub(corpus.len());
    }
    if corpus.contains(query) {
        return 6_000usize.saturating_sub(corpus.len());
    }
    fuzzy_subsequence_score(&corpus, query)
}

fn fuzzy_subsequence_score(haystack: &str, needle: &str) -> usize {
    let mut score = 0usize;
    let mut streak = 0usize;
    let mut chars = haystack.char_indices();
    let mut last_index = None;
    for needle_char in needle.chars() {
        let mut matched = false;
        for (index, hay_char) in chars.by_ref() {
            if hay_char != needle_char {
                streak = 0;
                continue;
            }
            matched = true;
            streak += 1;
            score += 10 + streak * 4;
            if let Some(previous) = last_index {
                if index == previous + 1 {
                    score += 8;
                }
            }
            last_index = Some(index);
            break;
        }
        if !matched {
            return 0;
        }
    }
    score.saturating_sub(haystack.len())
}

fn union_corpora(lhs: &[String], rhs: &[String]) -> Vec<String> {
    let mut merged = lhs.to_vec();
    merged.extend_from_slice(rhs);
    unique_corpora(&merged)
}

fn remove_corpus_from_pending_sample(
    memberships: &mut BTreeMap<String, SampleMembership>,
    sha256: &str,
    corpus: &str,
) {
    if let Some(membership) = memberships.get_mut(&sample_membership_key(sha256)) {
        membership.corpora.retain(|existing| existing != corpus);
        if membership.corpora.is_empty() {
            memberships.remove(&sample_membership_key(sha256));
        }
    }
}

fn remove_corpus_from_pending_memberships(
    memberships: &mut BTreeMap<String, SampleMembership>,
    corpus: &str,
) {
    memberships.retain(|_, membership| {
        membership.corpora.retain(|existing| existing != corpus);
        !membership.corpora.is_empty()
    });
}

fn prune_pending_entries_for_sample(
    entries: &mut BTreeMap<String, IndexEntry>,
    sha256: &str,
    corpus: &str,
) {
    entries.retain(|_, entry| {
        remove_corpus_from_entry(entry, sha256, Some(corpus));
        !entry.corpora.is_empty()
    });
}

fn prune_pending_entries_for_corpus(entries: &mut BTreeMap<String, IndexEntry>, corpus: &str) {
    entries.retain(|_, entry| {
        remove_corpus_from_entry(entry, "", Some(corpus));
        !entry.corpora.is_empty()
    });
}

fn remove_corpus_from_entry(entry: &mut IndexEntry, sha256: &str, corpus: Option<&str>) -> bool {
    let before = entry.corpora.clone();
    if sha256.is_empty() || entry.sha256 == sha256 {
        if let Some(corpus) = corpus {
            entry.corpora.retain(|existing| existing.corpus != corpus);
        }
    }
    entry.corpora != before
}

fn current_indexed_at() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn parse_indexed_at(value: &str) -> Option<DateTime<Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|date| date.with_timezone(&Utc))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SymbolMutation {
    Add,
    Remove,
    Replace,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CorpusMutation {
    Add,
    Replace,
}

fn resolve_query_corpora(index: &LocalIndex, requested: &[String]) -> Result<Vec<String>, Error> {
    if !requested.is_empty() {
        return Ok(requested.to_vec());
    }
    let corpora = index.corpora()?;
    if corpora.is_empty() {
        return Ok(vec!["default".to_string()]);
    }
    Ok(corpora)
}

fn map_query_collection(collection: QueryCollection) -> Collection {
    match collection {
        QueryCollection::Instruction => Collection::Instruction,
        QueryCollection::Block => Collection::Block,
        QueryCollection::Function => Collection::Function,
    }
}

fn search_expr_matches(result: &SearchResult, expr: &QueryExpr, root: &Option<SearchRoot>) -> bool {
    match expr {
        QueryExpr::Term(term) => search_term_matches(result, term, root),
        QueryExpr::Not(inner) => !search_expr_matches(result, inner, root),
        QueryExpr::And(lhs, rhs) => {
            search_expr_matches(result, lhs, root) && search_expr_matches(result, rhs, root)
        }
        QueryExpr::Or(lhs, rhs) => {
            search_expr_matches(result, lhs, root) || search_expr_matches(result, rhs, root)
        }
    }
}

fn search_term_matches(result: &SearchResult, term: &QueryTerm, root: &Option<SearchRoot>) -> bool {
    let value = term.value.trim();
    match term.field {
        QueryField::Sha256 => result.sha256().eq_ignore_ascii_case(value),
        QueryField::Embedding => result.embedding().eq_ignore_ascii_case(value),
        QueryField::Embeddings => count_query_matches(value, result.embeddings()),
        QueryField::Vector => matches!(root, Some(SearchRoot::Vector(_))),
        QueryField::Corpus => result.corpus().eq_ignore_ascii_case(value),
        QueryField::Collection => result.collection().as_str().eq_ignore_ascii_case(value),
        QueryField::Architecture => result.architecture().eq_ignore_ascii_case(value),
        QueryField::Address => parse_query_address(value) == Some(result.address()),
        QueryField::Date => query_date_matches(value, result.date()),
        QueryField::Size => query_size_matches(value, result.size()),
        QueryField::Symbol => result
            .symbol()
            .map(|symbol| symbol.eq_ignore_ascii_case(value))
            .unwrap_or(false),
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

fn count_query_matches(raw: &str, actual: u64) -> bool {
    let Some((operator, expected)) = parse_count_query(raw) else {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CountOperator {
    Eq,
    Gt,
    Gte,
    Lt,
    Lte,
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

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn mutate_symbol_attributes(
    attributes: &mut Vec<Value>,
    entity: Entity,
    address: u64,
    name: &str,
    mutation: SymbolMutation,
) -> (bool, bool) {
    let symbol_value = symbol_attribute_value(name, entity, address);
    let had_symbol = symbol_names_for_attributes(attributes, entity, address)
        .iter()
        .any(|existing| existing == name);
    match mutation {
        SymbolMutation::Add => {
            if had_symbol {
                return (false, true);
            }
            attributes.push(symbol_value);
            dedupe_attribute_values(attributes);
            (true, had_symbol)
        }
        SymbolMutation::Remove => {
            let before = attributes.len();
            attributes.retain(|attribute| {
                !symbol_attribute_matches(attribute, entity, address, Some(name))
            });
            (attributes.len() != before, had_symbol)
        }
        SymbolMutation::Replace => {
            let before = attributes.clone();
            attributes.retain(|attribute| !symbol_attribute_matches(attribute, entity, address, None));
            attributes.push(symbol_value);
            dedupe_attribute_values(attributes);
            (*attributes != before, had_symbol)
        }
    }
}

fn symbol_attribute_matches(
    value: &Value,
    entity: Entity,
    address: u64,
    name: Option<&str>,
) -> bool {
    let object = match value.as_object() {
        Some(object) => object,
        None => return false,
    };
    if object.get("type").and_then(Value::as_str) != Some("symbol") {
        return false;
    }
    if !symbol_type_matches_collection(
        object.get("symbol_type").and_then(Value::as_str).unwrap_or_default(),
        entity,
    ) {
        return false;
    }
    if object.get("address").and_then(Value::as_u64) != Some(address) {
        return false;
    }
    match name {
        Some(expected) => object.get("name").and_then(Value::as_str) == Some(expected),
        None => true,
    }
}

fn symbol_attribute_value(name: &str, entity: Entity, address: u64) -> Value {
    Attribute::Symbol(SymbolJson {
        type_: "symbol".to_string(),
        symbol_type: match entity {
            Collection::Instruction => SymbolType::Instruction,
            Collection::Block => SymbolType::Block,
            Collection::Function => SymbolType::Function,
        }
        .to_string(),
        name: name.to_string(),
        address,
    })
    .to_json_value()
}

fn instruction_selector_vector(
    graph: &Graph,
    instruction: &Instruction,
    selector: &str,
    processor_selector: Option<(&str, &str)>,
) -> Result<Option<Vec<f32>>, Error> {
    if let Some((processor_name, output_selector)) = processor_selector {
        return Ok(processor_output_vector(
            graph,
            ProcessorTarget::Instruction,
            instruction.address,
            processor_name,
            output_selector,
        ));
    }
    let processed = serde_json::to_value(instruction.process())
        .map_err(|error| Error::Serialization(error.to_string()))?;
    Ok(selector_vector(&processed, selector))
}

fn block_selector_vector(
    graph: &Graph,
    block: &Block<'_>,
    selector: &str,
    processor_selector: Option<(&str, &str)>,
) -> Result<Option<Vec<f32>>, Error> {
    if let Some((processor_name, output_selector)) = processor_selector {
        return Ok(processor_output_vector(
            graph,
            ProcessorTarget::Block,
            block.address(),
            processor_name,
            output_selector,
        ));
    }
    let processed = serde_json::to_value(block.process())
        .map_err(|error| Error::Serialization(error.to_string()))?;
    Ok(selector_vector(&processed, selector))
}

fn function_selector_vector(
    graph: &Graph,
    function: &Function<'_>,
    selector: &str,
    processor_selector: Option<(&str, &str)>,
) -> Result<Option<Vec<f32>>, Error> {
    if let Some((processor_name, output_selector)) = processor_selector {
        return Ok(processor_output_vector(
            graph,
            ProcessorTarget::Function,
            function.address,
            processor_name,
            output_selector,
        ));
    }
    let processed = serde_json::to_value(function.process())
        .map_err(|error| Error::Serialization(error.to_string()))?;
    Ok(selector_vector(&processed, selector))
}

fn processor_selector(selector: &str) -> Option<(&str, &str)> {
    let remainder = selector.strip_prefix("processors.")?;
    let (processor_name, output_selector) = remainder.split_once('.')?;
    if processor_name.is_empty() || output_selector.is_empty() {
        return None;
    }
    Some((processor_name, output_selector))
}

fn processor_output_vector(
    graph: &Graph,
    target: ProcessorTarget,
    address: u64,
    processor_name: &str,
    output_selector: &str,
) -> Option<Vec<f32>> {
    if graph
        .processor_output(target, address, processor_name)
        .is_none()
        && !crate::processor::enabled_processors_for_target(&graph.config, ProcessorTarget::Graph)
            .is_empty()
    {
        let _ = graph.process_graph();
    }
    let output = graph.processor_output(target, address, processor_name)?;
    selector_vector(&output, output_selector)
}

fn selector_value<'a>(value: &'a Value, selector: &str) -> Option<&'a Value> {
    let mut current = value;
    for part in selector.split('.') {
        if part.is_empty() {
            return None;
        }
        current = current.get(part)?;
    }
    Some(current)
}

fn selector_vector(value: &Value, selector: &str) -> Option<Vec<f32>> {
    let vector = selector_value(value, selector)?.as_array()?;
    vector
        .iter()
        .map(|value| value.as_f64().map(|item| item as f32))
        .collect()
}

fn entity_json_for_result(
    index: &LocalIndex,
    cache: &mut BTreeMap<(String, String), Graph>,
    corpus: &str,
    sha256: &str,
    entity: Entity,
    address: u64,
) -> Option<Value> {
    let key = (corpus.to_string(), sha256.to_string());
    if !cache.contains_key(&key) {
        let graph = index.load(corpus, sha256).ok()?;
        cache.insert(key.clone(), graph);
    }
    let graph = cache.get(&key)?;
    match entity {
        Entity::Instruction => serde_json::to_value(graph.get_instruction(address)?.process()).ok(),
        Entity::Block => serde_json::to_value(Block::new(address, graph).ok()?.process()).ok(),
        Entity::Function => {
            serde_json::to_value(Function::new(address, graph).ok()?.process()).ok()
        }
    }
}

fn object_id_for_value(entity: Entity, value: &Value) -> String {
    format!(
        "{}:{}",
        entity.as_str(),
        digest_hex(value.to_string().as_bytes())
    )
}

fn manual_object_id(entity: Entity, architecture: &str, sha256: &str, address: u64) -> String {
    object_id_for_value(
        entity,
        &serde_json::json!({
            "architecture": architecture,
            "sha256": sha256,
            "address": address,
        }),
    )
}

fn sample_key(sha256: &str) -> String {
    format!("samples/{}.bin", sha256)
}

fn graph_key(sha256: &str) -> String {
    format!("graphs/{}.json", sha256)
}

fn index_entry_key(entity: Entity, architecture: &str, object_id: &str) -> String {
    format!(
        "index/{}/{}/{}.json",
        entity.as_str(),
        architecture,
        object_id
    )
}

fn architecture_from_index_entry_key(key: &str) -> Option<String> {
    let remainder = key.strip_prefix("index/")?;
    let (_, remainder) = remainder.split_once('/')?;
    let (architecture, _) = remainder.split_once('/')?;
    Some(architecture.to_string())
}

fn sample_membership_key(sha256: &str) -> String {
    format!("memberships/samples/{}.json", sha256)
}

fn sha256_from_sample_membership_key(key: &str) -> Option<String> {
    key.strip_prefix("memberships/samples/")?
        .strip_suffix(".json")
        .map(ToString::to_string)
}

fn unique_corpora(items: &[String]) -> Vec<String> {
    let mut values = items.to_vec();
    values.sort();
    values.dedup();
    values
}

fn unique_samples(items: &[(String, String)]) -> Vec<(String, String)> {
    let mut values = items.to_vec();
    values.sort();
    values.dedup();
    values
}

fn merge_attribute_values(existing: &mut Vec<Value>, updates: &[Value]) {
    existing.extend_from_slice(updates);
    dedupe_attribute_values(existing);
}

fn dedupe_attribute_values(values: &mut Vec<Value>) {
    let mut seen = BTreeSet::new();
    values.retain(|value| seen.insert(value.to_string()));
}

fn symbol_names_for_attributes(attributes: &[Value], entity: Entity, address: u64) -> Vec<String> {
    let mut symbols = attributes
        .iter()
        .filter_map(|attribute| {
            let object = attribute.as_object()?;
            if object.get("type")?.as_str()? != "symbol" {
                return None;
            }
            if object.get("name")?.as_str()?.is_empty() {
                return None;
            }
            let symbol_type = object.get("symbol_type")?.as_str()?;
            if !symbol_type_matches_collection(symbol_type, entity) {
                return None;
            }
            let symbol_address = object.get("address")?.as_u64()?;
            if symbol_address != address {
                return None;
            }
            Some(object.get("name")?.as_str()?.to_string())
        })
        .collect::<Vec<_>>();
    symbols.sort();
    symbols.dedup();
    symbols
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controlflow::{Graph, Instruction};
    use crate::formats::SymbolJson;
    use crate::{Architecture, Config};
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::OnceLock;

    fn embeddings_processor_path(manifest_dir: &std::path::Path) -> PathBuf {
        let binary_name = if cfg!(windows) {
            "binlex-processor-embeddings.exe"
        } else {
            "binlex-processor-embeddings"
        };
        manifest_dir.join("target").join("debug").join(binary_name)
    }

    fn embeddings_processor_dir() -> String {
        static PROCESSOR_DIR: OnceLock<String> = OnceLock::new();

        PROCESSOR_DIR
            .get_or_init(|| {
                let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
                let processor_path = embeddings_processor_path(&manifest_dir);
                if !processor_path.exists() {
                    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
                    let mut command = Command::new(cargo);
                    command.current_dir(&manifest_dir);
                    command.env_remove("RUSTC_WRAPPER");
                    command.args([
                        "build",
                        "-p",
                        "binlex-processor-embeddings",
                        "--bin",
                        "binlex-processor-embeddings",
                    ]);
                    let status = command
                        .status()
                        .expect("cargo should build binlex-processor-embeddings");
                    assert!(
                        status.success(),
                        "binlex-processor-embeddings binary should build"
                    );
                }

                processor_path
                    .parent()
                    .expect("processor binary should have a parent directory")
                    .to_string_lossy()
                    .into_owned()
            })
            .clone()
    }

    fn build_single_return_graph() -> Graph {
        let processor_dir = embeddings_processor_dir();
        let mut config = Config::default();
        config.processors.enabled = true;
        config.processors.path = Some(processor_dir);
        let embeddings = config
            .processors
            .ensure_processor("embeddings")
            .expect("embeddings processor config should exist");
        embeddings.enabled = true;
        embeddings.instructions.enabled = false;
        embeddings.blocks.enabled = false;
        embeddings.functions.enabled = false;
        embeddings.graph.enabled = true;
        embeddings.transport.ipc.enabled = true;
        embeddings.transport.http.enabled = false;
        let mut graph = Graph::new(Architecture::AMD64, config.clone());
        let mut instruction = Instruction::create(0x1000, Architecture::AMD64, config);
        instruction.bytes = vec![0xC3];
        instruction.pattern = "c3".to_string();
        instruction.is_return = true;
        graph.insert_instruction(instruction);
        assert!(graph.set_block(0x1000));
        assert!(graph.set_function(0x1000));
        graph
    }

    fn symbol_attribute(name: &str, entity: Entity, address: u64) -> Attribute {
        Attribute::Symbol(SymbolJson {
            type_: "symbol".to_string(),
            symbol_type: match entity {
                Collection::Instruction => SymbolType::Instruction,
                Collection::Block => SymbolType::Block,
                Collection::Function => SymbolType::Function,
            }
            .to_string(),
            name: name.to_string(),
            address,
        })
    }

    fn test_vector(primary: usize) -> Vec<f32> {
        let mut vector = vec![0.0; 64];
        if primary < vector.len() {
            vector[primary] = 1.0;
        }
        vector
    }

    fn single_return_function() -> Function<'static> {
        let graph = Box::leak(Box::new(build_single_return_graph()));
        Function::new(0x1000, graph).expect("build function")
    }

    fn stage_vector_entry(
        client: &LocalIndex,
        corpora: &[String],
        collection: Entity,
        architecture: Architecture,
        vector: &[f32],
        sha256: &str,
        address: u64,
    ) {
        client
            .index_many(corpora, collection, architecture, vector, sha256, address, 0, &[])
            .expect("stage vector entry");
    }

    fn local_config_with_dimensions(root: &std::path::Path, dimensions: Option<usize>) -> Config {
        let mut config = Config::default();
        config.index.local.directory = root.to_string_lossy().into_owned();
        config.index.local.dimensions = dimensions;
        config
    }

    #[test]
    fn manual_vector_index_round_trip() {
        let root = std::env::temp_dir().join(format!(
            "binlex-local-store-manual-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let client = LocalIndex::with_options(Config::default(), Some(root.clone()), None)
            .expect("create local index client");
        let graph = build_single_return_graph();

        client
            .graph("corpus", "deadbeef", &graph, &[], None, None)
            .expect("stage graph");
        stage_vector_entry(
            &client,
            &["corpus".to_string()],
            Entity::Function,
            Architecture::AMD64,
            &test_vector(0),
            "deadbeef",
            0x1000,
        );
        client.commit().expect("commit staged entries");

        let hits = client
            .search(
                &["corpus".to_string()],
                &test_vector(0),
                Some(&[Entity::Function]),
                &[Architecture::AMD64],
                4,
            )
            .expect("search local index");

        assert_eq!(hits.len(), 1);
        assert_eq!(
            hits[0].object_id(),
            manual_object_id(Entity::Function, "amd64", "deadbeef", 0x1000)
        );
        assert_eq!(hits[0].sha256(), "deadbeef");
        assert_eq!(hits[0].address(), 0x1000);

        let restored = client.load("corpus", "deadbeef").expect("restore graph");
        assert_eq!(restored.functions().len(), 1);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn search_results_include_embedding_id_and_exact_count() {
        let root = std::env::temp_dir().join(format!(
            "binlex-local-store-embedding-count-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let client = LocalIndex::with_options(Config::default(), Some(root.clone()), None)
            .expect("create local index client");
        let graph = build_single_return_graph();
        let shared_vector = test_vector(7);

        for sha256 in ["alpha-sha", "beta-sha", "gamma-sha", "delta-sha"] {
            client
                .graph("demo", sha256, &graph, &[], None, None)
                .expect("stage graph");
        }
        stage_vector_entry(&client, &["demo".to_string()], Entity::Function, Architecture::AMD64, &shared_vector, "alpha-sha", 0x1000);
        stage_vector_entry(&client, &["demo".to_string()], Entity::Function, Architecture::AMD64, &shared_vector, "beta-sha", 0x2000);
        stage_vector_entry(&client, &["demo".to_string()], Entity::Block, Architecture::AMD64, &shared_vector, "gamma-sha", 0x3000);
        stage_vector_entry(&client, &["demo".to_string()], Entity::Function, Architecture::I386, &shared_vector, "delta-sha", 0x4000);
        client.commit().expect("commit entries");

        let hits = client
            .search(
                &["demo".to_string()],
                &shared_vector,
                Some(&[Entity::Function]),
                &[Architecture::AMD64],
                8,
            )
            .expect("search function embeddings");

        assert_eq!(hits.len(), 2);
        let expected_embedding = embedding_id_for_vector(&shared_vector);
        assert!(hits.iter().all(|hit| hit.embedding() == expected_embedding));
        assert!(hits.iter().all(|hit| hit.embeddings() == 2));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn embedding_search_pivots_to_exact_vector_group() {
        let root = std::env::temp_dir().join(format!(
            "binlex-local-store-embedding-search-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let client = LocalIndex::with_options(Config::default(), Some(root.clone()), None)
            .expect("create local index client");
        let graph = build_single_return_graph();
        let shared_vector = test_vector(9);

        for sha256 in ["alpha-sha", "beta-sha", "gamma-sha"] {
            client
                .graph("demo", sha256, &graph, &[], None, None)
                .expect("stage graph");
        }
        stage_vector_entry(&client, &["demo".to_string()], Entity::Function, Architecture::AMD64, &shared_vector, "alpha-sha", 0x1000);
        stage_vector_entry(&client, &["demo".to_string()], Entity::Function, Architecture::AMD64, &shared_vector, "beta-sha", 0x2000);
        stage_vector_entry(&client, &["demo".to_string()], Entity::Function, Architecture::AMD64, &test_vector(10), "gamma-sha", 0x3000);
        client.commit().expect("commit entries");

        let embedding = embedding_id_for_vector(&shared_vector);
        let hits = client
            .embedding_search(
                &["demo".to_string()],
                &embedding,
                Some(&[Entity::Function]),
                &[Architecture::AMD64],
                8,
            )
            .expect("search by embedding");

        assert_eq!(hits.len(), 2);
        assert!(hits.iter().all(|hit| hit.embedding() == embedding));
        assert!(hits.iter().all(|hit| hit.embeddings() == 2));
        assert!(hits.iter().all(|hit| hit.collection() == Entity::Function));
        assert!(hits.iter().all(|hit| hit.architecture() == "amd64"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn selector_graph_round_trip() {
        let root = std::env::temp_dir().join(format!(
            "binlex-local-store-selector-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let graph = build_single_return_graph();
        let vector = {
            let functions = graph.functions();
            let processed =
                serde_json::to_value(functions[0].process()).expect("serialize function");
            selector_vector(&processed, "processors.embeddings.vector").expect("function vector")
        };
        let client = LocalIndex::with_options(Config::default(), Some(root.clone()), None)
            .expect("create local index client");

        client
            .graph(
                "corpus",
                "feedface",
                &graph,
                &[],
                Some("processors.embeddings.vector"),
                None,
            )
            .expect("stage graph with selector");
        client.commit().expect("commit staged graph");

        let hits = client
            .search(
                &["corpus".to_string()],
                &vector,
                Some(&[Entity::Function]),
                &[Architecture::AMD64],
                4,
            )
            .expect("search local index");

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].sha256(), "feedface");
        assert_eq!(hits[0].address(), 0x1000);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn search_merges_multiple_corpora_and_default_entities() {
        let root = std::env::temp_dir().join(format!(
            "binlex-local-store-search-merge-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let client = LocalIndex::with_options(Config::default(), Some(root.clone()), None)
            .expect("create local index client");

        stage_vector_entry(&client, &["alpha".to_string()], Entity::Function, Architecture::AMD64, &test_vector(0), "alpha-sha", 0x1000);
        stage_vector_entry(&client, &["beta".to_string()], Entity::Block, Architecture::AMD64, &test_vector(0), "beta-sha", 0x2000);
        client.commit().expect("commit staged vectors");

        let hits = client
            .search(
                &["alpha".to_string(), "beta".to_string()],
                &test_vector(0),
                None,
                &[Architecture::AMD64],
                8,
            )
            .expect("search local index");

        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].score(), 1.0);
        assert_eq!(hits[1].score(), 1.0);
        assert!(
            hits.iter()
                .any(|hit| hit.collection() == Entity::Function && hit.sha256() == "alpha-sha")
        );
        assert!(
            hits.iter()
                .any(|hit| hit.collection() == Entity::Block && hit.sha256() == "beta-sha")
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn shared_entries_support_multiple_corpora_without_duplicate_objects() {
        let root = std::env::temp_dir().join(format!(
            "binlex-local-store-shared-corpora-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let client = LocalIndex::with_options(Config::default(), Some(root.clone()), None)
            .expect("create local index client");
        let corpora = vec!["malware".to_string(), "plugx".to_string()];

        stage_vector_entry(
            &client,
            &corpora,
            Entity::Function,
            Architecture::AMD64,
            &test_vector(0),
            "shared-sha",
            0x1000,
        );
        client.commit().expect("commit shared vector");

        let keys = client
            .object_store
            .list_prefix("index/function/amd64/")
            .expect("list shared index entries");
        assert_eq!(keys.len(), 1);

        let hits = client
            .search(
                &["malware".to_string(), "plugx".to_string()],
                &test_vector(0),
                Some(&[Entity::Function]),
                &[Architecture::AMD64],
                8,
            )
            .expect("search shared object across corpora");
        assert_eq!(hits.len(), 2);
        assert!(hits.iter().any(|hit| hit.corpus() == "malware"));
        assert!(hits.iter().any(|hit| hit.corpus() == "plugx"));

        client
            .delete("malware", "shared-sha")
            .expect("delete malware membership");
        client.commit().expect("commit membership removal");

        let remaining_hits = client
            .search(
                &["malware".to_string(), "plugx".to_string()],
                &test_vector(0),
                Some(&[Entity::Function]),
                &[Architecture::AMD64],
                8,
            )
            .expect("search after one corpus removal");
        assert_eq!(remaining_hits.len(), 1);
        assert_eq!(remaining_hits[0].corpus(), "plugx");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn uses_configured_directory_when_override_is_absent() {
        let root = std::env::temp_dir().join(format!(
            "binlex-local-store-config-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let mut config = Config::default();
        config.index.local.directory = root.to_string_lossy().into_owned();

        let client = LocalIndex::new(config).expect("create local index client");

        assert_eq!(client.object_store.root(), root.join("object_store"));
        assert_eq!(client.lancedb.root(), root.join("lancedb"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn repeat_graph_indexing_does_not_duplicate_search_results() {
        let root = std::env::temp_dir().join(format!(
            "binlex-local-store-repeat-index-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let client = LocalIndex::with_options(Config::default(), Some(root.clone()), None)
            .expect("create local index client");
        let graph = build_single_return_graph();
        let vector = {
            let functions = graph.functions();
            let processed =
                serde_json::to_value(functions[0].process()).expect("serialize function");
            selector_vector(&processed, "processors.embeddings.vector").expect("function vector")
        };

        for _ in 0..3 {
            client
                .graph(
                    "default",
                    "repeat-sha",
                    &graph,
                    &[],
                    Some("processors.embeddings.vector"),
                    None,
                )
                .expect("stage graph with selector");
            client.commit().expect("commit repeated graph");
        }

        let hits = client
            .search(
                &["default".to_string()],
                &vector,
                Some(&[Entity::Function]),
                &[Architecture::AMD64],
                8,
            )
            .expect("search local index after repeat indexing");

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].sha256(), "repeat-sha");
        assert_eq!(hits[0].address(), 0x1000);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn search_results_expose_indexed_date() {
        let root = std::env::temp_dir().join(format!(
            "binlex-local-store-indexed-date-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let client = LocalIndex::with_options(Config::default(), Some(root.clone()), None)
            .expect("create local index client");

        stage_vector_entry(&client, &["demo".to_string()], Entity::Function, Architecture::AMD64, &test_vector(0), "dated-sha", 0x1000);
        client.commit().expect("commit vector");

        let hits = client
            .search(
                &["demo".to_string()],
                &test_vector(0),
                Some(&[Entity::Function]),
                &[Architecture::AMD64],
                4,
            )
            .expect("search dated result");

        assert_eq!(hits.len(), 1);
        assert!(hits[0].date() > Utc.timestamp_opt(0, 0).single().unwrap());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn add_remove_replace_symbol_updates_results() {
        let root = std::env::temp_dir().join(format!(
            "binlex-local-store-symbol-mutation-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let client = LocalIndex::with_options(Config::default(), Some(root.clone()), None)
            .expect("create local index client");

        client.put(b"sample-bytes").expect("store sample");
        let function = single_return_function();
        client
            .function(
                &["demo".to_string()],
                &function,
                &test_vector(0),
                &digest_hex(b"sample-bytes"),
                &[symbol_attribute("alpha", Entity::Function, 0x1000)],
            )
            .expect("stage function");
        client.commit().expect("commit function");

        client
            .add_symbol(&digest_hex(b"sample-bytes"), 0x1000, "beta")
            .expect("add symbol");
        let add_hits = client
            .exact_search(
                &["demo".to_string()],
                &digest_hex(b"sample-bytes"),
                Some(&[Entity::Function]),
                &[Architecture::AMD64],
                8,
            )
            .expect("search symbols after add");
        assert_eq!(add_hits.len(), 2);
        assert!(add_hits.iter().any(|hit| hit.symbol() == Some("alpha")));
        assert!(add_hits.iter().any(|hit| hit.symbol() == Some("beta")));

        client
            .remove_symbol(&digest_hex(b"sample-bytes"), 0x1000, "alpha")
            .expect("remove symbol");
        let remove_hits = client
            .exact_search(
                &["demo".to_string()],
                &digest_hex(b"sample-bytes"),
                Some(&[Entity::Function]),
                &[Architecture::AMD64],
                8,
            )
            .expect("search symbols after remove");
        assert_eq!(remove_hits.len(), 1);
        assert_eq!(remove_hits[0].symbol(), Some("beta"));

        client
            .replace_symbol(&digest_hex(b"sample-bytes"), 0x1000, "gamma")
            .expect("replace symbol");
        let replace_hits = client
            .exact_search(
                &["demo".to_string()],
                &digest_hex(b"sample-bytes"),
                Some(&[Entity::Function]),
                &[Architecture::AMD64],
                8,
            )
            .expect("search symbols after replace");
        assert_eq!(replace_hits.len(), 1);
        assert_eq!(replace_hits[0].symbol(), Some("gamma"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn query_supports_pagination() {
        let root = std::env::temp_dir().join(format!(
            "binlex-local-store-query-pagination-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let client = LocalIndex::with_options(Config::default(), Some(root.clone()), None)
            .expect("create local index client");

        client.put(b"first").expect("store first sample");
        client.put(b"second").expect("store second sample");
        let function = single_return_function();
        client
            .function(
                &["demo".to_string()],
                &function,
                &test_vector(0),
                &digest_hex(b"first"),
                &[],
            )
            .expect("stage first function");
        client
            .function(
                &["demo".to_string()],
                &function,
                &test_vector(1),
                &digest_hex(b"second"),
                &[],
            )
            .expect("stage second function");
        client.commit().expect("commit functions");

        let page_one = client
            .query("collection:function", 1, 1)
            .expect("query first page");
        let page_two = client
            .query("collection:function", 1, 2)
            .expect("query second page");

        assert_eq!(page_one.len(), 1);
        assert_eq!(page_two.len(), 1);
        assert_ne!(page_one[0].sha256(), page_two[0].sha256());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn query_filters_by_entity_size() {
        let root = std::env::temp_dir().join(format!(
            "binlex-local-store-size-query-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let client = LocalIndex::with_options(Config::default(), Some(root.clone()), None)
            .expect("create local index client");
        let sha256 = client.put(b"size-sample").expect("store sample");
        let function = single_return_function();
        client
            .function(
                &["default".to_string()],
                &function,
                &test_vector(0),
                &sha256,
                &[],
            )
            .expect("stage function");
        client.commit().expect("commit function");

        let all_hits = client
            .query("collection:function", 8, 1)
            .expect("query functions");
        assert_eq!(all_hits.len(), 1);
        assert_eq!(all_hits[0].size(), 1);

        let sized_hits = client
            .query("size:1 AND collection:function", 8, 1)
            .expect("query size match");
        assert_eq!(sized_hits.len(), 1);
        assert_eq!(sized_hits[0].size(), 1);

        let empty_hits = client
            .query("size:>1 AND collection:function", 8, 1)
            .expect("query size mismatch");
        assert!(empty_hits.is_empty());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn add_and_replace_corpus_update_sample_results() {
        let root = std::env::temp_dir().join(format!(
            "binlex-local-store-corpus-mutation-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let client = LocalIndex::with_options(Config::default(), Some(root.clone()), None)
            .expect("create local index client");

        let sha256 = client.put(b"corpus-sample").expect("store sample");
        let function = single_return_function();
        client
            .function(
                &["default".to_string()],
                &function,
                &test_vector(0),
                &sha256,
                &[],
            )
            .expect("stage function");
        client.commit().expect("commit function");

        client
            .add_corpus(&sha256, "malware")
            .expect("add corpus");
        let corpora = client.corpora().expect("list corpora after add");
        assert!(corpora.iter().any(|corpus| corpus == "default"));
        assert!(corpora.iter().any(|corpus| corpus == "malware"));
        let unqualified_hits = client
            .query("collection:function", 8, 1)
            .expect("query all corpora after add corpus");
        assert!(unqualified_hits.iter().any(|hit| hit.corpus() == "default"));
        assert!(unqualified_hits.iter().any(|hit| hit.corpus() == "malware"));
        let add_hits = client
            .query("corpus:malware AND collection:function", 8, 1)
            .expect("query after add corpus");
        assert!(add_hits.iter().any(|hit| hit.corpus() == "malware"));

        client
            .replace_corpus(&sha256, "clean")
            .expect("replace corpus");
        let corpora = client.corpora().expect("list corpora after replace");
        assert_eq!(corpora, vec!["clean".to_string()]);
        let replace_hits = client
            .query("corpus:clean AND collection:function", 8, 1)
            .expect("query after replace corpus");
        assert_eq!(replace_hits.len(), 1);
        assert_eq!(replace_hits[0].corpus(), "clean");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn rename_corpus_updates_index_globally() {
        let root = std::env::temp_dir().join(format!(
            "binlex-local-store-corpus-rename-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let client = LocalIndex::with_options(Config::default(), Some(root.clone()), None)
            .expect("create local index client");

        let first = client.put(b"first-corpus").expect("store first sample");
        let second = client.put(b"second-corpus").expect("store second sample");
        let function = single_return_function();
        client
            .function(
                &["malware".to_string()],
                &function,
                &test_vector(0),
                &first,
                &[],
            )
            .expect("stage first function");
        client
            .function(
                &["malware".to_string()],
                &function,
                &test_vector(1),
                &second,
                &[],
            )
            .expect("stage second function");
        client.commit().expect("commit functions");

        client
            .rename_corpus("malware", "malware-renamed")
            .expect("rename corpus");

        let corpora = client.corpora().expect("list corpora");
        assert!(corpora.iter().any(|corpus| corpus == "malware-renamed"));
        assert!(!corpora.iter().any(|corpus| corpus == "malware"));

        let hits = client
            .query("collection:function", 8, 1)
            .expect("query after rename corpus");
        assert_eq!(hits.len(), 2);
        assert!(hits.iter().all(|hit| hit.corpus() == "malware-renamed"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn reindex_updates_result_date() {
        let root = std::env::temp_dir().join(format!(
            "binlex-local-store-reindex-date-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let client = LocalIndex::with_options(Config::default(), Some(root.clone()), None)
            .expect("create local index client");

        stage_vector_entry(&client, &["demo".to_string()], Entity::Function, Architecture::AMD64, &test_vector(0), "dated-sha", 0x1000);
        client.commit().expect("commit first vector");

        let first_date = client
            .search(
                &["demo".to_string()],
                &test_vector(0),
                Some(&[Entity::Function]),
                &[Architecture::AMD64],
                4,
            )
            .expect("search first dated result")[0]
            .date();

        std::thread::sleep(std::time::Duration::from_secs(1));

        stage_vector_entry(&client, &["demo".to_string()], Entity::Function, Architecture::AMD64, &test_vector(0), "dated-sha", 0x1000);
        client.commit().expect("commit second vector");

        let second_date = client
            .search(
                &["demo".to_string()],
                &test_vector(0),
                Some(&[Entity::Function]),
                &[Architecture::AMD64],
                4,
            )
            .expect("search second dated result")[0]
            .date();

        assert!(second_date > first_date);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn same_corpus_distinct_symbols_expand_flat_results_without_duplicate_objects() {
        let root = std::env::temp_dir().join(format!(
            "binlex-local-store-symbols-same-corpus-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let client = LocalIndex::with_options(Config::default(), Some(root.clone()), None)
            .expect("create local index client");
        let function = single_return_function();

        client
            .function(
                &["alpha".to_string()],
                &function,
                &test_vector(0),
                "alpha-sha",
                &[symbol_attribute("malware_steal", Entity::Function, 0x1000)],
            )
            .expect("stage first symbol");
        client.commit().expect("commit first symbol");

        client
            .function(
                &["alpha".to_string()],
                &function,
                &test_vector(1),
                "alpha-sha",
                &[symbol_attribute(
                    "malware_stealer",
                    Entity::Function,
                    0x1000,
                )],
            )
            .expect("stage second symbol");
        client.commit().expect("commit second symbol");

        let keys = client
            .object_store
            .list_prefix("index/function/amd64/")
            .expect("list canonical function entries");
        assert_eq!(keys.len(), 1);

        let hits = client
            .search(
                &["alpha".to_string()],
                &test_vector(1),
                Some(&[Entity::Function]),
                &[Architecture::AMD64],
                8,
            )
            .expect("search same-corpus symbols");
        assert_eq!(hits.len(), 2);
        assert!(hits.iter().all(|hit| hit.corpus() == "alpha"));
        assert!(hits.iter().any(|hit| hit.symbol() == Some("malware_steal")));
        assert!(
            hits.iter()
                .any(|hit| hit.symbol() == Some("malware_stealer"))
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn cross_corpus_symbols_expand_flat_results_per_corpus() {
        let root = std::env::temp_dir().join(format!(
            "binlex-local-store-symbols-cross-corpus-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let client = LocalIndex::with_options(Config::default(), Some(root.clone()), None)
            .expect("create local index client");
        let function = single_return_function();

        client
            .function(
                &["person_a".to_string()],
                &function,
                &test_vector(0),
                "shared-sha",
                &[symbol_attribute("malware_steal", Entity::Function, 0x1000)],
            )
            .expect("stage corpus a symbol");
        client.commit().expect("commit corpus a symbol");

        client
            .function(
                &["person_b".to_string()],
                &function,
                &test_vector(0),
                "shared-sha",
                &[symbol_attribute(
                    "malware_stealer",
                    Entity::Function,
                    0x1000,
                )],
            )
            .expect("stage corpus b symbol");
        client.commit().expect("commit corpus b symbol");

        let hits = client
            .search(
                &["person_a".to_string(), "person_b".to_string()],
                &test_vector(0),
                Some(&[Entity::Function]),
                &[Architecture::AMD64],
                8,
            )
            .expect("search cross-corpus symbols");
        assert_eq!(hits.len(), 2);
        assert!(
            hits.iter()
                .any(|hit| { hit.corpus() == "person_a" && hit.symbol() == Some("malware_steal") })
        );
        assert!(
            hits.iter().any(|hit| {
                hit.corpus() == "person_b" && hit.symbol() == Some("malware_stealer")
            })
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn explicit_directory_overrides_configured_directory() {
        let configured_root = std::env::temp_dir().join(format!(
            "binlex-local-store-configured-test-{}",
            std::process::id()
        ));
        let override_root = std::env::temp_dir().join(format!(
            "binlex-local-store-override-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&configured_root);
        let _ = std::fs::remove_dir_all(&override_root);
        let mut config = Config::default();
        config.index.local.directory = configured_root.to_string_lossy().into_owned();

        let client = LocalIndex::with_options(config, Some(override_root.clone()), None)
            .expect("create local index client");

        assert_eq!(
            client.object_store.root(),
            override_root.join("object_store")
        );
        assert_eq!(client.lancedb.root(), override_root.join("lancedb"));
        assert!(!configured_root.exists());

        let _ = std::fs::remove_dir_all(&configured_root);
        let _ = std::fs::remove_dir_all(&override_root);
    }

    #[test]
    fn rejects_manual_vector_with_wrong_configured_dimensions() {
        let root = std::env::temp_dir().join(format!(
            "binlex-local-store-dims-write-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let client = LocalIndex::new(local_config_with_dimensions(&root, Some(4)))
            .expect("create local index client");

        let error = client
            .index_many(
                &["demo".to_string()],
                Entity::Function,
                Architecture::AMD64,
                &test_vector(0),
                "deadbeef",
                0x1000,
                0,
                &[],
            )
            .expect_err("reject wrong vector length");

        assert_eq!(
            error.to_string(),
            "local index configuration error: vector length 64 does not match configured index.local.dimensions 4"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn rejects_search_vector_with_wrong_configured_dimensions() {
        let root = std::env::temp_dir().join(format!(
            "binlex-local-store-dims-search-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let client = LocalIndex::new(local_config_with_dimensions(&root, Some(4)))
            .expect("create local index client");

        let error = client
            .search(
                &["demo".to_string()],
                &[1.0, 0.0, 0.0],
                Some(&[Entity::Function]),
                &[Architecture::AMD64],
                4,
            )
            .expect_err("reject wrong search vector length");

        assert_eq!(
            error.to_string(),
            "local index configuration error: vector length 3 does not match configured index.local.dimensions 4"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn rejects_selector_vectors_with_wrong_configured_dimensions() {
        let root = std::env::temp_dir().join(format!(
            "binlex-local-store-dims-selector-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let graph = build_single_return_graph();
        let client = LocalIndex::new(local_config_with_dimensions(&root, Some(8)))
            .expect("create local index client");

        let error = client
            .graph(
                "demo",
                "feedface",
                &graph,
                &[],
                Some("processors.embeddings.vector"),
                None,
            )
            .expect_err("reject selector vector length mismatch");

        assert!(
            error
                .to_string()
                .contains("does not match configured index.local.dimensions 8")
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn rejects_existing_table_dimension_mismatch_on_open() {
        let root = std::env::temp_dir().join(format!(
            "binlex-local-store-dims-existing-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);

        let writer = LocalIndex::new(local_config_with_dimensions(&root, Some(3)))
            .expect("create local index writer");
        writer
            .index_many(
                &["demo".to_string()],
                Entity::Function,
                Architecture::AMD64,
                &[1.0, 0.0, 0.0],
                "deadbeef",
                0x1000,
                0,
                &[],
            )
            .expect("stage vector");
        writer.commit().expect("commit vector");

        let error = match LocalIndex::new(local_config_with_dimensions(&root, Some(4))) {
            Ok(_) => panic!("reject existing table dimension mismatch"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("existing local index table function__amd64 uses dimensions 3, but index.local.dimensions is 4")
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}
