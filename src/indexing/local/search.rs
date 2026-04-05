use super::LocalIndex;
use super::lancedb as local_lancedb;
use super::support::{
    SearchHitContext, SearchHydration, architecture_from_index_entry_key, build_search_result,
    corpus_match_score, embedding_id_for_vector, index_entry_key, manual_object_id,
    normalize_corpora, page_search_results, push_search_hits, symbol_names_for_attributes,
};
use super::types::{DEFAULT_INDEX_GRAPH_COLLECTIONS, Error, IndexEntry, SearchResult};
use crate::controlflow::{Block, Function, Graph};
use crate::databases::localdb::EntityMetadataRecord;
use crate::indexing::{Collection, Entity};
use crate::math::similarity::cosine;
use std::collections::{BTreeMap, BTreeSet};

impl LocalIndex {
    pub fn nearest(
        &self,
        corpora: &[String],
        vector: &[f32],
        collections: Option<&[Collection]>,
        architectures: &[crate::Architecture],
        limit: usize,
    ) -> Result<Vec<SearchResult>, Error> {
        self.nearest_page(corpora, vector, collections, architectures, 0, limit)
    }

    pub fn nearest_page(
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
        let allowed_keys = self.allowed_entity_keys_for_corpora(&corpora)?;
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
                let rows = match local_lancedb::search(
                    &self.lancedb,
                    *entity,
                    &architecture,
                    vector,
                    offset.saturating_add(limit),
                ) {
                    Ok(rows) => rows,
                    Err(error) if error.to_string().contains("not found") => continue,
                    Err(error) => return Err(Error::LanceDb(error.to_string())),
                };
                for row in rows {
                    let key = index_entry_key(*entity, &architecture, &row.object_id);
                    if !allowed_keys.contains(&key) {
                        continue;
                    }
                    let score = cosine(vector, &row.vector);
                    let metadata = self
                        .localdb
                        .entity_metadata_get(*entity, &architecture, &row.object_id)
                        .map_err(|error| Error::LocalDb(error.to_string()))?
                        .ok_or_else(|| {
                            Error::NotFound(format!(
                                "entity metadata {}/{}/{}",
                                entity.as_str(),
                                architecture,
                                row.object_id
                            ))
                        })?;
                    let entry = metadata_entry(&metadata, Some(row.vector.clone()));
                    let (sha256, address) = match (row.sha256.as_deref(), row.address) {
                        (Some(sha256), Some(address)) => (sha256.to_string(), address),
                        _ => (metadata.sha256.clone(), metadata.address),
                    };
                    let row_corpora = self
                        .localdb
                        .entity_corpus_list(&sha256, *entity, &architecture, address)
                        .map_err(|error| Error::LocalDb(error.to_string()))?;
                    if !row_corpora
                        .iter()
                        .any(|corpus| requested_corpora.contains(corpus))
                    {
                        continue;
                    }
                    push_search_hits(
                        &mut hits,
                        self,
                        &mut graph_cache,
                        SearchHitContext {
                            object_id: &row.object_id,
                            entity: *entity,
                            architecture: &architecture,
                            sha256: &sha256,
                            address,
                            entry: &entry,
                            vector: &row.vector,
                            score,
                        },
                        &row_corpora,
                        SearchHydration::Summary,
                    );
                }
            }
        }
        hits.sort_by(|lhs, rhs| rhs.score.total_cmp(&lhs.score));
        self.attach_embedding_metadata(page_search_results(hits, offset, limit))
    }

    pub fn corpus_list(&self) -> Result<Vec<String>, Error> {
        self.localdb
            .entity_corpus_distinct()
            .map_err(|error| Error::LocalDb(error.to_string()))
    }

    pub fn corpus_search(&self, query: &str, limit: usize) -> Result<Vec<String>, Error> {
        let mut corpora = self.corpus_list()?;
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
        let allowed_keys = self.allowed_entity_keys_for_corpora(&corpora)?;
        let requested_architectures = architectures
            .iter()
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>();
        let entries = self
            .localdb
            .entity_metadata_search(
                Some(sha256),
                collections,
                &requested_architectures.iter().cloned().collect::<Vec<_>>(),
            )
            .map_err(|error| Error::LocalDb(error.to_string()))?;
        let mut hits = Vec::new();
        let mut graph_cache = BTreeMap::<(String, String), Graph>::new();
        for metadata in entries {
            let key = index_entry_key(
                metadata.collection,
                &metadata.architecture,
                &metadata.object_id,
            );
            if !allowed_keys.contains(&key) {
                continue;
            }
            let entry = metadata_entry(&metadata, None);
            let entry_corpora = self
                .localdb
                .entity_corpus_list(
                    &entry.sha256,
                    entry.entity,
                    &entry.architecture,
                    entry.address,
                )
                .map_err(|error| Error::LocalDb(error.to_string()))?;
            if entry_corpora
                .iter()
                .any(|corpus| requested_corpora.contains(corpus))
            {
                push_search_hits(
                    &mut hits,
                    self,
                    &mut graph_cache,
                    SearchHitContext {
                        object_id: &entry.object_id,
                        entity: entry.entity,
                        architecture: &entry.architecture,
                        sha256: &entry.sha256,
                        address: entry.address,
                        entry: &entry,
                        vector: &entry.vector,
                        score: 1.0,
                    },
                    &entry_corpora,
                    SearchHydration::Summary,
                );
            }
        }
        hits.sort_by(|lhs, rhs| {
            rhs.score
                .total_cmp(&lhs.score)
                .then_with(|| lhs.corpus().cmp(rhs.corpus()))
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
        let allowed_keys = self.allowed_entity_keys_for_corpora(&corpora)?;
        let requested_architectures = architectures
            .iter()
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>();
        let entries = self
            .localdb
            .entity_metadata_search(
                None,
                collections,
                &requested_architectures.iter().cloned().collect::<Vec<_>>(),
            )
            .map_err(|error| Error::LocalDb(error.to_string()))?;
        let mut hits = Vec::new();
        let mut graph_cache = BTreeMap::<(String, String), Graph>::new();
        for metadata in entries {
            let key = index_entry_key(
                metadata.collection,
                &metadata.architecture,
                &metadata.object_id,
            );
            if !allowed_keys.contains(&key) {
                continue;
            }
            let entry = metadata_entry(&metadata, None);
            if embedding_id_for_vector(&entry.vector) != embedding {
                continue;
            }
            let entry_corpora = self
                .localdb
                .entity_corpus_list(
                    &entry.sha256,
                    entry.entity,
                    &entry.architecture,
                    entry.address,
                )
                .map_err(|error| Error::LocalDb(error.to_string()))?;
            if entry_corpora
                .iter()
                .any(|corpus| requested_corpora.contains(corpus))
            {
                push_search_hits(
                    &mut hits,
                    self,
                    &mut graph_cache,
                    SearchHitContext {
                        object_id: &entry.object_id,
                        entity: entry.entity,
                        architecture: &entry.architecture,
                        sha256: &entry.sha256,
                        address: entry.address,
                        entry: &entry,
                        vector: &entry.vector,
                        score: 1.0,
                    },
                    &entry_corpora,
                    SearchHydration::Summary,
                );
            }
        }
        hits.sort_by(|lhs, rhs| {
            rhs.score
                .total_cmp(&lhs.score)
                .then_with(|| lhs.corpus().cmp(rhs.corpus()))
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
        let allowed_keys = self.allowed_entity_keys_for_corpora(&corpora)?;
        let requested_architectures = architectures
            .iter()
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>();
        let entries = self
            .localdb
            .entity_metadata_search(
                None,
                collections,
                &requested_architectures.iter().cloned().collect::<Vec<_>>(),
            )
            .map_err(|error| Error::LocalDb(error.to_string()))?;
        let mut hits = Vec::new();
        let mut graph_cache = BTreeMap::<(String, String), Graph>::new();
        for metadata in entries {
            let key = index_entry_key(
                metadata.collection,
                &metadata.architecture,
                &metadata.object_id,
            );
            if !allowed_keys.contains(&key) {
                continue;
            }
            let entry = metadata_entry(&metadata, None);
            let entry_corpora = self
                .localdb
                .entity_corpus_list(
                    &entry.sha256,
                    entry.entity,
                    &entry.architecture,
                    entry.address,
                )
                .map_err(|error| Error::LocalDb(error.to_string()))?;
            if entry_corpora
                .iter()
                .any(|corpus| requested_corpora.contains(corpus))
            {
                push_search_hits(
                    &mut hits,
                    self,
                    &mut graph_cache,
                    SearchHitContext {
                        object_id: &entry.object_id,
                        entity: entry.entity,
                        architecture: &entry.architecture,
                        sha256: &entry.sha256,
                        address: entry.address,
                        entry: &entry,
                        vector: &entry.vector,
                        score: 1.0,
                    },
                    &entry_corpora,
                    SearchHydration::Summary,
                );
            }
        }
        hits.sort_by(|lhs, rhs| {
            rhs.score
                .total_cmp(&lhs.score)
                .then_with(|| lhs.corpus().cmp(rhs.corpus()))
                .then_with(|| lhs.architecture.cmp(&rhs.architecture))
                .then_with(|| lhs.entity.cmp(&rhs.entity))
                .then_with(|| lhs.address.cmp(&rhs.address))
        });
        self.attach_embedding_metadata(page_search_results(hits, offset, limit))
    }

    fn entity_architectures(&self, entity: Entity) -> Result<Vec<String>, Error> {
        let prefix = format!("index/{}/", entity.as_str());
        let mut architectures = self
            .store
            .object_list(&prefix)
            .map_err(|error| Error::LocalStore(error.to_string()))?
            .into_iter()
            .filter_map(|key| architecture_from_index_entry_key(&key))
            .collect::<Vec<_>>();
        architectures.sort();
        architectures.dedup();
        Ok(architectures)
    }

    fn attach_embedding_metadata(
        &self,
        mut hits: Vec<SearchResult>,
    ) -> Result<Vec<SearchResult>, Error> {
        if hits.is_empty() {
            return Ok(hits);
        }
        let mut counts = BTreeMap::<(Collection, String, String), u64>::new();
        for hit in &mut hits {
            let embedding = embedding_id_for_vector(&hit.vector);
            let key = (hit.entity, hit.architecture.clone(), embedding.clone());
            let count = if let Some(count) = counts.get(&key) {
                *count
            } else {
                let count = self
                    .localdb
                    .embedding_count_get(hit.entity, &hit.architecture, &embedding)
                    .map_err(|error| Error::LocalDb(error.to_string()))?;
                counts.insert(key, count);
                count
            };
            hit.embeddings = count;
            hit.embedding = embedding;
        }
        Ok(hits)
    }

    pub fn result_detail(
        &self,
        sha256: &str,
        collection: Collection,
        architecture: &str,
        address: u64,
        symbol: Option<&str>,
    ) -> Result<SearchResult, Error> {
        let object_id = manual_object_id(collection, architecture, sha256, address);
        let metadata = self
            .localdb
            .entity_metadata_get(collection, architecture, &object_id)
            .map_err(|error| Error::LocalDb(error.to_string()))?
            .ok_or_else(|| {
                Error::NotFound(format!(
                    "entity metadata {}/{}/{}",
                    collection.as_str(),
                    architecture,
                    object_id
                ))
            })?;
        let entry = metadata_entry(&metadata, None);
        let corpora = self
            .localdb
            .entity_corpus_list(
                &entry.sha256,
                entry.entity,
                &entry.architecture,
                entry.address,
            )
            .map_err(|error| Error::LocalDb(error.to_string()))?;
        let mut cache = BTreeMap::<(String, String), Graph>::new();
        let resolved_symbol = symbol.map(ToString::to_string).or_else(|| {
            symbol_names_for_attributes(&entry.attributes, entry.entity, entry.address)
                .into_iter()
                .next()
        });
        let result = build_search_result(
            self,
            &mut cache,
            &SearchHitContext {
                object_id: &entry.object_id,
                entity: entry.entity,
                architecture: &entry.architecture,
                sha256: &entry.sha256,
                address: entry.address,
                entry: &entry,
                vector: &entry.vector,
                score: 1.0,
            },
            &corpora,
            resolved_symbol,
            SearchHydration::Summary,
        );
        Ok(self
            .attach_embedding_metadata(vec![result])?
            .into_iter()
            .next()
            .expect("detail result should exist"))
    }

    pub fn symbol_list(
        &self,
        sha256: &str,
        collection: Collection,
        architecture: &str,
        address: u64,
    ) -> Result<Vec<String>, Error> {
        let object_id = manual_object_id(collection, architecture, sha256, address);
        let metadata = self
            .localdb
            .entity_metadata_get(collection, architecture, &object_id)
            .map_err(|error| Error::LocalDb(error.to_string()))?
            .ok_or_else(|| {
                Error::NotFound(format!(
                    "entity metadata {}/{}/{}",
                    collection.as_str(),
                    architecture,
                    object_id
                ))
            })?;
        let entry = metadata_entry(&metadata, None);
        Ok(symbol_names_for_attributes(
            &entry.attributes,
            entry.entity,
            entry.address,
        ))
    }

    pub fn result_children(
        &self,
        parent: &SearchResult,
        child_collection: Collection,
    ) -> Result<Vec<SearchResult>, Error> {
        let mut addresses = self
            .localdb
            .entity_child_addresses(
                parent.sha256(),
                parent.architecture(),
                parent.collection(),
                parent.address(),
                child_collection,
            )
            .map_err(|error| Error::LocalDb(error.to_string()))?;
        if addresses.is_empty() {
            addresses = self.fallback_child_addresses_from_graph(parent, child_collection)?;
        }
        addresses
            .into_iter()
            .map(|address| {
                self.result_detail(
                    parent.sha256(),
                    child_collection,
                    parent.architecture(),
                    address,
                    None,
                )
            })
            .collect()
    }

    fn fallback_child_addresses_from_graph(
        &self,
        parent: &SearchResult,
        child_collection: Collection,
    ) -> Result<Vec<u64>, Error> {
        let corpus = parent.corpus();
        if corpus.is_empty() {
            return Ok(Vec::new());
        }
        let graph = self.sample_load(corpus, parent.sha256())?;
        let mut addresses = match (parent.collection(), child_collection) {
            (Collection::Function, Collection::Block) => {
                let function = Function::new(parent.address(), &graph)
                    .map_err(|error| Error::Graph(error.to_string()))?;
                function
                    .blocks()
                    .into_iter()
                    .map(|block| block.address())
                    .collect::<Vec<_>>()
            }
            (Collection::Function, Collection::Instruction) => {
                let function = Function::new(parent.address(), &graph)
                    .map_err(|error| Error::Graph(error.to_string()))?;
                function
                    .blocks()
                    .into_iter()
                    .flat_map(|block| {
                        block
                            .instructions()
                            .into_iter()
                            .map(|instruction| instruction.address)
                    })
                    .collect::<Vec<_>>()
            }
            (Collection::Block, Collection::Instruction) => {
                let block = Block::new(parent.address(), &graph)
                    .map_err(|error| Error::Graph(error.to_string()))?;
                block
                    .instructions()
                    .into_iter()
                    .map(|instruction| instruction.address)
                    .collect::<Vec<_>>()
            }
            _ => Vec::new(),
        };
        addresses.sort_unstable();
        addresses.dedup();
        Ok(addresses)
    }

    fn allowed_entity_keys_for_corpora(
        &self,
        corpora: &[String],
    ) -> Result<BTreeSet<String>, Error> {
        let refs = self
            .localdb
            .entity_corpus_refs_for_any(corpora)
            .map_err(|error| Error::LocalDb(error.to_string()))?;
        Ok(refs
            .into_iter()
            .map(|entry| {
                let object_id = manual_object_id(
                    entry.collection,
                    &entry.architecture,
                    &entry.sha256,
                    entry.address,
                );
                index_entry_key(entry.collection, &entry.architecture, &object_id)
            })
            .collect())
    }
}

fn metadata_entry(
    metadata: &EntityMetadataRecord,
    vector_override: Option<Vec<f32>>,
) -> IndexEntry {
    IndexEntry {
        object_id: metadata.object_id.clone(),
        entity: metadata.collection,
        architecture: metadata.architecture.clone(),
        username: metadata.username.clone(),
        sha256: metadata.sha256.clone(),
        address: metadata.address,
        size: metadata.size,
        cyclomatic_complexity: metadata.cyclomatic_complexity,
        average_instructions_per_block: metadata.average_instructions_per_block,
        number_of_instructions: metadata.number_of_instructions,
        number_of_blocks: metadata.number_of_blocks,
        markov: metadata.markov,
        entropy: metadata.entropy,
        contiguous: metadata.contiguous,
        chromosome_entropy: metadata.chromosome_entropy,
        timestamp: metadata.timestamp.clone(),
        vector: vector_override.unwrap_or_else(|| metadata.vector.clone()),
        explicit_corpora: None,
        attributes: metadata.attributes.clone(),
    }
}
