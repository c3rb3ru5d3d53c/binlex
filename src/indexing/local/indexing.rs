use super::LocalIndex;
use super::lancedb as local_lancedb;
use super::support::{
    accumulate_entry, block_selector_vector, embedding_id_for_vector, entity_metrics_for_block,
    entity_metrics_for_function, function_selector_vector, graph_key, index_entry_key,
    instruction_selector_vector, manual_object_id, normalize_index_corpora, process_attributes,
    processor_selector, set_entity_corpora, symbol_names_for_attributes, unique_corpora,
    unique_samples,
};
use super::types::{
    DEFAULT_INDEX_GRAPH_COLLECTIONS, EntityMetrics, Error, IndexEntry, StoredGraphRecord,
};
use crate::controlflow::{
    Block, BlockJson, Function, FunctionJson, Graph, Instruction, InstructionJson,
};
use crate::databases::localdb::{
    EmbeddingCountDelta, EntityChildWrite, EntityCorpusWrite, EntityMetadataRecord,
};
use crate::indexing::{Collection, Entity};
use crate::metadata::Attribute;
use crate::processor::ProcessorTarget;
use crate::storage::localstore;
use rayon::prelude::*;
use std::collections::{BTreeMap, BTreeSet};

fn entity_child_write_key(
    sha256: &str,
    architecture: &str,
    parent_collection: Collection,
    parent_address: u64,
    child_collection: Collection,
) -> String {
    format!(
        "{}:{}:{}:{}:{}",
        sha256,
        architecture,
        parent_collection.as_str(),
        parent_address,
        child_collection.as_str()
    )
}

fn set_entity_children(
    pending: &mut BTreeMap<String, EntityChildWrite>,
    sha256: &str,
    architecture: &str,
    parent_collection: Collection,
    parent_address: u64,
    child_collection: Collection,
    child_addresses: Vec<u64>,
) {
    let key = entity_child_write_key(
        sha256,
        architecture,
        parent_collection,
        parent_address,
        child_collection,
    );
    let mut child_addresses = child_addresses
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    child_addresses.sort_unstable();
    pending.insert(
        key,
        EntityChildWrite {
            sha256: sha256.to_string(),
            architecture: architecture.to_string(),
            parent_collection,
            parent_address,
            child_collection,
            child_addresses,
        },
    );
}

#[derive(Clone)]
struct StagedGraphEntry {
    key: String,
    entry: IndexEntry,
    corpora: Vec<String>,
}

impl LocalIndex {
    pub fn graph(
        &self,
        sha256: &str,
        graph: &Graph,
        attributes: &[Attribute],
        selector: Option<&str>,
        collections: Option<&[Collection]>,
    ) -> Result<(), Error> {
        self.graph_as(
            sha256,
            graph,
            attributes,
            selector,
            collections,
            "anonymous",
        )
    }

    pub fn graph_as(
        &self,
        sha256: &str,
        graph: &Graph,
        attributes: &[Attribute],
        selector: Option<&str>,
        collections: Option<&[Collection]>,
        username: &str,
    ) -> Result<(), Error> {
        self.graph_many_as(
            &["default".to_string()],
            sha256,
            graph,
            attributes,
            selector,
            collections,
            username,
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
        self.graph_many_as(
            corpora,
            sha256,
            graph,
            attributes,
            selector,
            collections,
            "anonymous",
        )
    }

    pub fn graph_many_as(
        &self,
        corpora: &[String],
        sha256: &str,
        graph: &Graph,
        attributes: &[Attribute],
        selector: Option<&str>,
        collections: Option<&[Collection]>,
        username: &str,
    ) -> Result<(), Error> {
        self.stage_graph_json_attributes(
            corpora,
            sha256,
            graph,
            process_attributes(attributes),
            attributes,
            selector,
            collections,
            username,
        )
    }

    pub fn instruction(
        &self,
        instruction: &Instruction,
        vector: &[f32],
        sha256: &str,
        attributes: &[Attribute],
    ) -> Result<(), Error> {
        self.instruction_as(instruction, vector, sha256, attributes, "anonymous")
    }

    pub fn instruction_as(
        &self,
        instruction: &Instruction,
        vector: &[f32],
        sha256: &str,
        attributes: &[Attribute],
        username: &str,
    ) -> Result<(), Error> {
        self.instruction_many_as(
            &["default".to_string()],
            instruction,
            vector,
            sha256,
            attributes,
            username,
        )
    }

    pub fn instruction_many(
        &self,
        corpora: &[String],
        instruction: &Instruction,
        vector: &[f32],
        sha256: &str,
        attributes: &[Attribute],
    ) -> Result<(), Error> {
        self.instruction_many_as(
            corpora,
            instruction,
            vector,
            sha256,
            attributes,
            "anonymous",
        )
    }

    pub fn instruction_many_as(
        &self,
        corpora: &[String],
        instruction: &Instruction,
        vector: &[f32],
        sha256: &str,
        attributes: &[Attribute],
        username: &str,
    ) -> Result<(), Error> {
        self.index_many(
            corpora,
            Entity::Instruction,
            instruction.architecture,
            username,
            vector,
            sha256,
            instruction.address,
            instruction.size() as u64,
            None,
            attributes,
        )
    }

    pub fn instruction_json(
        &self,
        instruction: &InstructionJson,
        vector: &[f32],
        sha256: &str,
        attributes: &[Attribute],
    ) -> Result<(), Error> {
        self.instruction_json_as(instruction, vector, sha256, attributes, "anonymous")
    }

    pub fn instruction_json_as(
        &self,
        instruction: &InstructionJson,
        vector: &[f32],
        sha256: &str,
        attributes: &[Attribute],
        username: &str,
    ) -> Result<(), Error> {
        self.instruction_json_many_as(
            &["default".to_string()],
            instruction,
            vector,
            sha256,
            attributes,
            username,
        )
    }

    pub fn instruction_json_many(
        &self,
        corpora: &[String],
        instruction: &InstructionJson,
        vector: &[f32],
        sha256: &str,
        attributes: &[Attribute],
    ) -> Result<(), Error> {
        self.instruction_json_many_as(
            corpora,
            instruction,
            vector,
            sha256,
            attributes,
            "anonymous",
        )
    }

    pub fn instruction_json_many_as(
        &self,
        corpora: &[String],
        instruction: &InstructionJson,
        vector: &[f32],
        sha256: &str,
        attributes: &[Attribute],
        username: &str,
    ) -> Result<(), Error> {
        self.index_many(
            corpora,
            Entity::Instruction,
            crate::Architecture::from_string(&instruction.architecture)
                .map_err(|error| Error::Validation(error.to_string()))?,
            username,
            vector,
            sha256,
            instruction.address,
            instruction.size as u64,
            None,
            attributes,
        )
    }

    pub fn block(
        &self,
        block: &Block,
        vector: &[f32],
        sha256: &str,
        attributes: &[Attribute],
    ) -> Result<(), Error> {
        self.block_as(block, vector, sha256, attributes, "anonymous")
    }

    pub fn block_as(
        &self,
        block: &Block,
        vector: &[f32],
        sha256: &str,
        attributes: &[Attribute],
        username: &str,
    ) -> Result<(), Error> {
        self.block_many_as(
            &["default".to_string()],
            block,
            vector,
            sha256,
            attributes,
            username,
        )
    }

    pub fn block_many(
        &self,
        corpora: &[String],
        block: &Block,
        vector: &[f32],
        sha256: &str,
        attributes: &[Attribute],
    ) -> Result<(), Error> {
        self.block_many_as(corpora, block, vector, sha256, attributes, "anonymous")
    }

    pub fn block_many_as(
        &self,
        corpora: &[String],
        block: &Block,
        vector: &[f32],
        sha256: &str,
        attributes: &[Attribute],
        username: &str,
    ) -> Result<(), Error> {
        self.index_many(
            corpora,
            Entity::Block,
            block.cfg.architecture,
            username,
            vector,
            sha256,
            block.address,
            block.size() as u64,
            Some(entity_metrics_for_block(block)),
            attributes,
        )
    }

    pub fn block_json(
        &self,
        block: &BlockJson,
        vector: &[f32],
        sha256: &str,
        attributes: &[Attribute],
    ) -> Result<(), Error> {
        self.block_json_as(block, vector, sha256, attributes, "anonymous")
    }

    pub fn block_json_as(
        &self,
        block: &BlockJson,
        vector: &[f32],
        sha256: &str,
        attributes: &[Attribute],
        username: &str,
    ) -> Result<(), Error> {
        self.block_json_many_as(
            &["default".to_string()],
            block,
            vector,
            sha256,
            attributes,
            username,
        )
    }

    pub fn block_json_many(
        &self,
        corpora: &[String],
        block: &BlockJson,
        vector: &[f32],
        sha256: &str,
        attributes: &[Attribute],
    ) -> Result<(), Error> {
        self.block_json_many_as(corpora, block, vector, sha256, attributes, "anonymous")
    }

    pub fn block_json_many_as(
        &self,
        corpora: &[String],
        block: &BlockJson,
        vector: &[f32],
        sha256: &str,
        attributes: &[Attribute],
        username: &str,
    ) -> Result<(), Error> {
        self.index_many(
            corpora,
            Entity::Block,
            crate::Architecture::from_string(&block.architecture)
                .map_err(|error| Error::Validation(error.to_string()))?,
            username,
            vector,
            sha256,
            block.address,
            block.size as u64,
            Some(EntityMetrics {
                cyclomatic_complexity: None,
                average_instructions_per_block: None,
                number_of_instructions: Some(block.number_of_instructions as u64),
                number_of_blocks: None,
                markov: None,
                entropy: block.entropy,
                chromosome_entropy: None,
                contiguous: Some(block.contiguous),
            }),
            attributes,
        )
    }

    pub fn function(
        &self,
        function: &Function,
        vector: &[f32],
        sha256: &str,
        attributes: &[Attribute],
    ) -> Result<(), Error> {
        self.function_as(function, vector, sha256, attributes, "anonymous")
    }

    pub fn function_as(
        &self,
        function: &Function,
        vector: &[f32],
        sha256: &str,
        attributes: &[Attribute],
        username: &str,
    ) -> Result<(), Error> {
        self.function_many_as(
            &["default".to_string()],
            function,
            vector,
            sha256,
            attributes,
            username,
        )
    }

    pub fn function_many(
        &self,
        corpora: &[String],
        function: &Function,
        vector: &[f32],
        sha256: &str,
        attributes: &[Attribute],
    ) -> Result<(), Error> {
        self.function_many_as(corpora, function, vector, sha256, attributes, "anonymous")
    }

    pub fn function_many_as(
        &self,
        corpora: &[String],
        function: &Function,
        vector: &[f32],
        sha256: &str,
        attributes: &[Attribute],
        username: &str,
    ) -> Result<(), Error> {
        self.index_many(
            corpora,
            Entity::Function,
            function.cfg.architecture,
            username,
            vector,
            sha256,
            function.address,
            function.size() as u64,
            Some(entity_metrics_for_function(function)),
            attributes,
        )
    }

    pub fn function_json(
        &self,
        function: &FunctionJson,
        vector: &[f32],
        sha256: &str,
        attributes: &[Attribute],
    ) -> Result<(), Error> {
        self.function_json_as(function, vector, sha256, attributes, "anonymous")
    }

    pub fn function_json_as(
        &self,
        function: &FunctionJson,
        vector: &[f32],
        sha256: &str,
        attributes: &[Attribute],
        username: &str,
    ) -> Result<(), Error> {
        self.function_json_many_as(
            &["default".to_string()],
            function,
            vector,
            sha256,
            attributes,
            username,
        )
    }

    pub fn function_json_many(
        &self,
        corpora: &[String],
        function: &FunctionJson,
        vector: &[f32],
        sha256: &str,
        attributes: &[Attribute],
    ) -> Result<(), Error> {
        self.function_json_many_as(corpora, function, vector, sha256, attributes, "anonymous")
    }

    pub fn function_json_many_as(
        &self,
        corpora: &[String],
        function: &FunctionJson,
        vector: &[f32],
        sha256: &str,
        attributes: &[Attribute],
        username: &str,
    ) -> Result<(), Error> {
        self.index_many(
            corpora,
            Entity::Function,
            crate::Architecture::from_string(&function.architecture)
                .map_err(|error| Error::Validation(error.to_string()))?,
            username,
            vector,
            sha256,
            function.address,
            function.size as u64,
            Some(EntityMetrics {
                cyclomatic_complexity: Some(function.cyclomatic_complexity as u64),
                average_instructions_per_block: Some(function.average_instructions_per_block),
                number_of_instructions: Some(function.number_of_instructions as u64),
                number_of_blocks: Some(function.number_of_blocks as u64),
                markov: None,
                entropy: function.entropy,
                chromosome_entropy: None,
                contiguous: Some(function.contiguous),
            }),
            attributes,
        )
    }

    pub(super) fn index_many(
        &self,
        corpora: &[String],
        collection: Collection,
        architecture: crate::Architecture,
        username: &str,
        vector: &[f32],
        sha256: &str,
        address: u64,
        size: u64,
        metrics: Option<EntityMetrics>,
        attributes: &[Attribute],
    ) -> Result<(), Error> {
        if vector.is_empty() {
            return Err(Error::InvalidConfiguration("vector must not be empty"));
        }
        self.validate_vector_dimensions(vector)?;
        if sha256.trim().is_empty() {
            return Err(Error::InvalidConfiguration("sha256 must not be empty"));
        }
        let corpora = normalize_index_corpora(corpora)?;
        let object_id = manual_object_id(collection, &architecture.to_string(), sha256, address);
        let attributes = attributes
            .iter()
            .map(Attribute::to_json_value)
            .collect::<Vec<_>>();
        let mut pending = self.pending.lock().unwrap();
        let key = index_entry_key(collection, &architecture.to_string(), &object_id);
        accumulate_entry(
            &mut pending.entries,
            key.clone(),
            collection,
            &architecture.to_string(),
            username,
            object_id,
            sha256,
            address,
            size,
            metrics.as_ref(),
            vector.to_vec(),
            Some(&corpora),
            &attributes,
        );
        set_entity_corpora(&mut pending.entity_corpora, &key, &corpora);
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
            self.store
                .object_put_json(key, record)
                .map_err(|error| Error::LocalStore(error.to_string()))?;
        }
        let mut grouped_rows = BTreeMap::<(Entity, String), Vec<local_lancedb::Row>>::new();
        let mut committed_entry_keys = BTreeSet::<String>::new();
        let mut entity_corpus_writes = Vec::<EntityCorpusWrite>::new();
        let entity_child_writes = pending
            .entity_children
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let mut metadata_writes = Vec::<EntityMetadataRecord>::new();
        let mut embedding_deltas = Vec::<EmbeddingCountDelta>::new();
        for (key, staged) in &pending.entries {
            committed_entry_keys.insert(key.clone());
            let previous_entry = match self.store.object_get_json::<IndexEntry>(key) {
                Ok(existing) => Some(existing),
                Err(localstore::Error::NotFound(_)) => None,
                Err(error) => return Err(Error::LocalStore(error.to_string())),
            };
            let previous_embedding = previous_entry.as_ref().map(|entry| {
                (
                    entry.entity,
                    entry.architecture.clone(),
                    embedding_id_for_vector(&entry.vector),
                )
            });
            let mut entry = match previous_entry {
                Some(existing) => existing,
                None => IndexEntry {
                    object_id: staged.object_id.clone(),
                    entity: staged.entity,
                    architecture: staged.architecture.clone(),
                    username: staged.username.clone(),
                    sha256: staged.sha256.clone(),
                    address: staged.address,
                    size: staged.size,
                    cyclomatic_complexity: staged.cyclomatic_complexity,
                    average_instructions_per_block: staged.average_instructions_per_block,
                    number_of_instructions: staged.number_of_instructions,
                    number_of_blocks: staged.number_of_blocks,
                    markov: staged.markov,
                    entropy: staged.entropy,
                    contiguous: staged.contiguous,
                    chromosome_entropy: staged.chromosome_entropy,
                    collection_tag_count: staged.collection_tag_count,
                    collection_tags: staged.collection_tags.clone(),
                    collection_comment_count: staged.collection_comment_count,
                    timestamp: staged.timestamp.clone(),
                    vector: staged.vector.clone(),
                    explicit_corpora: None,
                    attributes: Vec::new(),
                },
            };
            if let Some(staged_explicit) = &staged.explicit_corpora {
                let mut merged_explicit = entry.explicit_corpora.clone().unwrap_or_default();
                merged_explicit.extend(staged_explicit.clone());
                entry.explicit_corpora = Some(super::support::unique_corpora(&merged_explicit));
            }
            entry.attributes.extend(staged.attributes.clone());
            super::support::dedupe_attribute_values(&mut entry.attributes);
            entry.username = staged.username.clone();
            entry.sha256 = staged.sha256.clone();
            entry.address = staged.address;
            entry.size = staged.size;
            entry.cyclomatic_complexity = staged.cyclomatic_complexity;
            entry.average_instructions_per_block = staged.average_instructions_per_block;
            entry.number_of_instructions = staged.number_of_instructions;
            entry.number_of_blocks = staged.number_of_blocks;
            entry.entropy = staged.entropy;
            entry.contiguous = staged.contiguous;
            entry.chromosome_entropy = staged.chromosome_entropy;
            entry.collection_tag_count = staged.collection_tag_count;
            entry.collection_tags = staged.collection_tags.clone();
            entry.collection_comment_count = staged.collection_comment_count;
            entry.timestamp = staged.timestamp.clone();
            entry.vector = staged.vector.clone();
            self.store
                .object_put_json(key, &entry)
                .map_err(|error| Error::LocalStore(error.to_string()))?;
            let current_embedding = (
                entry.entity,
                entry.architecture.clone(),
                embedding_id_for_vector(&entry.vector),
            );
            match previous_embedding {
                Some((previous_collection, previous_architecture, previous_embedding))
                    if previous_collection == current_embedding.0
                        && previous_architecture == current_embedding.1
                        && previous_embedding == current_embedding.2 => {}
                Some((previous_collection, previous_architecture, previous_embedding)) => {
                    embedding_deltas.push(EmbeddingCountDelta {
                        collection: previous_collection,
                        architecture: previous_architecture,
                        embedding: previous_embedding,
                        delta: -1,
                    });
                    embedding_deltas.push(EmbeddingCountDelta {
                        collection: current_embedding.0,
                        architecture: current_embedding.1.clone(),
                        embedding: current_embedding.2.clone(),
                        delta: 1,
                    });
                }
                None => {
                    embedding_deltas.push(EmbeddingCountDelta {
                        collection: current_embedding.0,
                        architecture: current_embedding.1.clone(),
                        embedding: current_embedding.2.clone(),
                        delta: 1,
                    });
                }
            }
            let corpora = if let Some(explicit) = &entry.explicit_corpora {
                explicit.clone()
            } else {
                pending.entity_corpora.get(key).cloned().unwrap_or_default()
            };
            entity_corpus_writes.push(EntityCorpusWrite {
                sha256: entry.sha256.clone(),
                collection: entry.entity,
                architecture: entry.architecture.clone(),
                address: entry.address,
                corpora,
                username: entry.username.clone(),
                timestamp: entry.timestamp.clone(),
            });
            metadata_writes.push(EntityMetadataRecord {
                object_id: entry.object_id.clone(),
                sha256: entry.sha256.clone(),
                collection: entry.entity,
                architecture: entry.architecture.clone(),
                username: entry.username.clone(),
                address: entry.address,
                size: entry.size,
                cyclomatic_complexity: entry.cyclomatic_complexity,
                average_instructions_per_block: entry.average_instructions_per_block,
                number_of_instructions: entry.number_of_instructions,
                number_of_blocks: entry.number_of_blocks,
                markov: entry.markov,
                entropy: entry.entropy,
                contiguous: entry.contiguous,
                chromosome_entropy: entry.chromosome_entropy,
                collection_tag_count: entry.collection_tag_count,
                collection_tags: entry.collection_tags.clone(),
                collection_comment_count: entry.collection_comment_count,
                timestamp: entry.timestamp.clone(),
                vector: entry.vector.clone(),
                attributes: entry.attributes.clone(),
            });
            grouped_rows
                .entry((entry.entity, entry.architecture.clone()))
                .or_default()
                .push(local_lancedb::Row {
                    object_id: entry.object_id.clone(),
                    username: entry.username.clone(),
                    sha256: Some(entry.sha256.clone()),
                    address: Some(entry.address),
                    vector: entry.vector.clone(),
                });
        }
        for (key, corpora) in &pending.entity_corpora {
            if committed_entry_keys.contains(key) {
                continue;
            }
            let entry = match self.store.object_get_json::<IndexEntry>(key) {
                Ok(entry) => entry,
                Err(localstore::Error::NotFound(_)) => continue,
                Err(error) => return Err(Error::LocalStore(error.to_string())),
            };
            let effective_corpora = if let Some(explicit) = &entry.explicit_corpora {
                explicit.clone()
            } else {
                corpora.clone()
            };
            entity_corpus_writes.push(EntityCorpusWrite {
                sha256: entry.sha256.clone(),
                collection: entry.entity,
                architecture: entry.architecture.clone(),
                address: entry.address,
                corpora: effective_corpora,
                username: entry.username.clone(),
                timestamp: entry.timestamp.clone(),
            });
        }
        self.localdb
            .apply_index_commit(
                &entity_corpus_writes,
                &entity_child_writes,
                &metadata_writes,
                &embedding_deltas,
            )
            .map_err(|error| Error::LocalDb(error.to_string()))?;
        for metadata in &metadata_writes {
            for symbol in symbol_names_for_attributes(
                &metadata.attributes,
                metadata.collection,
                metadata.address,
            ) {
                self.localdb
                    .symbol_add(&symbol, Some(&metadata.timestamp), None)
                    .map_err(|error| Error::LocalDb(error.to_string()))?;
            }
        }
        for ((collection, architecture), rows) in grouped_rows {
            local_lancedb::upsert_rows(&self.lancedb, collection, &architecture, &rows)
                .map_err(|error| Error::LanceDb(error.to_string()))?;
        }
        self.clear();
        Ok(())
    }

    pub fn clear(&self) {
        let mut pending = self.pending.lock().unwrap();
        pending.graphs.clear();
        pending.entries.clear();
        pending.entity_corpora.clear();
        pending.entity_children.clear();
        pending.deleted_samples.clear();
        pending.deleted_corpora.clear();
    }

    fn stage_graph_json_attributes(
        &self,
        corpora: &[String],
        sha256: &str,
        graph: &Graph,
        attributes: Option<serde_json::Value>,
        entity_attributes: &[Attribute],
        selector: Option<&str>,
        collections: Option<&[Collection]>,
        username: &str,
    ) -> Result<(), Error> {
        if sha256.trim().is_empty() {
            return Err(Error::InvalidConfiguration("sha256 must not be empty"));
        }
        let corpora = normalize_index_corpora(corpora)?;
        let record = StoredGraphRecord {
            attributes,
            snapshot: graph.snapshot(),
        };
        let staged_entries = if let Some(selector) = selector {
            if selector.trim().is_empty() {
                return Err(Error::InvalidConfiguration("selector must not be empty"));
            }
            self.stage_graph_selected_vectors(
                &corpora,
                sha256,
                graph,
                entity_attributes,
                selector,
                collections,
                username,
            )?
        } else {
            Vec::new()
        };
        let mut pending = self.pending.lock().unwrap();
        pending.graphs.insert(graph_key(sha256), record);
        let architecture = graph.architecture.to_string();
        for function in graph.functions() {
            let blocks = function.blocks();
            set_entity_children(
                &mut pending.entity_children,
                sha256,
                &architecture,
                Collection::Function,
                function.address,
                Collection::Block,
                blocks.iter().map(|block| block.address()).collect(),
            );
            set_entity_children(
                &mut pending.entity_children,
                sha256,
                &architecture,
                Collection::Function,
                function.address,
                Collection::Instruction,
                blocks
                    .into_iter()
                    .flat_map(|block| {
                        block
                            .instructions()
                            .into_iter()
                            .map(|instruction| instruction.address)
                    })
                    .collect(),
            );
        }
        for block in graph.blocks() {
            set_entity_children(
                &mut pending.entity_children,
                sha256,
                &architecture,
                Collection::Block,
                block.address(),
                Collection::Instruction,
                block
                    .instructions()
                    .into_iter()
                    .map(|instruction| instruction.address)
                    .collect(),
            );
        }
        if let Some(selector) = selector {
            let _ = selector;
            for staged in staged_entries {
                pending.entries.insert(staged.key.clone(), staged.entry);
                set_entity_corpora(&mut pending.entity_corpora, &staged.key, &staged.corpora);
            }
        }
        Ok(())
    }

    fn stage_graph_selected_vectors(
        &self,
        corpora: &[String],
        sha256: &str,
        graph: &Graph,
        attributes: &[Attribute],
        selector: &str,
        collections: Option<&[Collection]>,
        username: &str,
    ) -> Result<Vec<StagedGraphEntry>, Error> {
        let selected = collections
            .unwrap_or(DEFAULT_INDEX_GRAPH_COLLECTIONS)
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let attribute_map = build_graph_attribute_map(attributes);
        let processor_selector = self.prepare_graph_selector_outputs(graph, selector, &selected)?;
        let architecture = graph.architecture.to_string();
        let functions = graph.functions();
        functions
            .into_par_iter()
            .map(|function| {
                let mut staged = Vec::<StagedGraphEntry>::new();
                let function_markov = function.markov();
                if selected.contains(&Entity::Function) {
                    if let Some(vector) =
                        function_selector_vector(graph, &function, selector, processor_selector)?
                    {
                        self.validate_vector_dimensions(&vector)?;
                        staged.push(build_staged_graph_entry(
                            Entity::Function,
                            &architecture,
                            username,
                            sha256,
                            function.address,
                            function.size() as u64,
                            Some(entity_metrics_for_function(&function)),
                            vector,
                            attribute_map
                                .get(&(Entity::Function, function.address))
                                .cloned()
                                .unwrap_or_default(),
                            corpora,
                        ));
                    }
                }
                for block in function.blocks() {
                    if selected.contains(&Entity::Block) {
                        if let Some(vector) =
                            block_selector_vector(graph, &block, selector, processor_selector)?
                        {
                            self.validate_vector_dimensions(&vector)?;
                            let mut metrics = entity_metrics_for_block(&block);
                            metrics.markov = function_markov.get(&block.address()).copied();
                            staged.push(build_staged_graph_entry(
                                Entity::Block,
                                &architecture,
                                username,
                                sha256,
                                block.address(),
                                block.size() as u64,
                                Some(metrics),
                                vector,
                                attribute_map
                                    .get(&(Entity::Block, block.address()))
                                    .cloned()
                                    .unwrap_or_default(),
                                corpora,
                            ));
                        }
                    }
                    if selected.contains(&Entity::Instruction) {
                        for instruction in block.instructions() {
                            let Some(vector) = instruction_selector_vector(
                                graph,
                                &instruction,
                                selector,
                                processor_selector,
                            )?
                            else {
                                continue;
                            };
                            self.validate_vector_dimensions(&vector)?;
                            staged.push(build_staged_graph_entry(
                                Entity::Instruction,
                                &architecture,
                                username,
                                sha256,
                                instruction.address,
                                instruction.size() as u64,
                                None,
                                vector,
                                attribute_map
                                    .get(&(Entity::Instruction, instruction.address))
                                    .cloned()
                                    .unwrap_or_default(),
                                corpora,
                            ));
                        }
                    }
                }
                Ok::<Vec<StagedGraphEntry>, Error>(staged)
            })
            .try_reduce(Vec::new, |mut acc, mut staged| {
                acc.append(&mut staged);
                Ok(acc)
            })
    }

    fn prepare_graph_selector_outputs<'a>(
        &self,
        graph: &Graph,
        selector: &'a str,
        selected: &BTreeSet<Collection>,
    ) -> Result<Option<(&'a str, &'a str)>, Error> {
        let Some((processor_name, output_selector)) = processor_selector(selector) else {
            return Ok(None);
        };
        let need_instruction = selected.contains(&Entity::Instruction)
            && graph.instructions().into_iter().any(|instruction| {
                graph
                    .processor_output(
                        ProcessorTarget::Instruction,
                        instruction.address,
                        processor_name,
                    )
                    .is_none()
            });
        let need_block = selected.contains(&Entity::Block)
            && graph.blocks().into_iter().any(|block| {
                graph
                    .processor_output(ProcessorTarget::Block, block.address(), processor_name)
                    .is_none()
            });
        let need_function = selected.contains(&Entity::Function)
            && graph.functions().into_iter().any(|function| {
                graph
                    .processor_output(ProcessorTarget::Function, function.address, processor_name)
                    .is_none()
            });
        if need_instruction || need_block || need_function {
            graph
                .process_graph()
                .map_err(|error| Error::Graph(error.to_string()))?;
        }
        if need_instruction {
            graph
                .process_instructions()
                .map_err(|error| Error::Graph(error.to_string()))?;
        }
        if need_block {
            graph
                .process_blocks()
                .map_err(|error| Error::Graph(error.to_string()))?;
        }
        if need_function {
            graph
                .process_functions()
                .map_err(|error| Error::Graph(error.to_string()))?;
        }
        Ok(Some((processor_name, output_selector)))
    }
}

fn build_graph_attribute_map(
    attributes: &[Attribute],
) -> BTreeMap<(Entity, u64), Vec<serde_json::Value>> {
    let mut map = BTreeMap::<(Entity, u64), Vec<serde_json::Value>>::new();
    for attribute in attributes {
        if let Attribute::Symbol(symbol) = attribute {
            let entity = match symbol.symbol_type.as_str() {
                value if value == crate::metadata::SymbolType::Instruction.as_str() => {
                    Entity::Instruction
                }
                value if value == crate::metadata::SymbolType::Block.as_str() => Entity::Block,
                value if value == crate::metadata::SymbolType::Function.as_str() => {
                    Entity::Function
                }
                _ => continue,
            };
            map.entry((entity, symbol.address))
                .or_default()
                .push(attribute.to_json_value());
        }
    }
    map
}

fn build_staged_graph_entry(
    entity: Entity,
    architecture: &str,
    username: &str,
    sha256: &str,
    address: u64,
    size: u64,
    metrics: Option<EntityMetrics>,
    vector: Vec<f32>,
    attributes: Vec<serde_json::Value>,
    corpora: &[String],
) -> StagedGraphEntry {
    let object_id = manual_object_id(entity, architecture, sha256, address);
    let key = index_entry_key(entity, architecture, &object_id);
    let timestamp = super::support::current_timestamp();
    StagedGraphEntry {
        key,
        entry: IndexEntry {
            object_id,
            entity,
            architecture: architecture.to_string(),
            username: username.to_string(),
            sha256: sha256.to_string(),
            address,
            size,
            cyclomatic_complexity: metrics
                .as_ref()
                .and_then(|value| value.cyclomatic_complexity),
            average_instructions_per_block: metrics
                .as_ref()
                .and_then(|value| value.average_instructions_per_block),
            number_of_instructions: metrics
                .as_ref()
                .and_then(|value| value.number_of_instructions),
            number_of_blocks: metrics.as_ref().and_then(|value| value.number_of_blocks),
            markov: metrics.as_ref().and_then(|value| value.markov),
            entropy: metrics.as_ref().and_then(|value| value.entropy),
            contiguous: metrics.as_ref().and_then(|value| value.contiguous),
            chromosome_entropy: metrics.as_ref().and_then(|value| value.chromosome_entropy),
            collection_tag_count: 0,
            collection_tags: Vec::new(),
            collection_comment_count: 0,
            timestamp,
            vector,
            explicit_corpora: None,
            attributes,
        },
        corpora: corpora.to_vec(),
    }
}
