use super::LocalIndex;
use super::lancedb as local_lancedb;
use super::support::{
    is_sha256, mutate_symbol_attributes, normalize_index_corpora, prune_pending_entries_for_corpus,
    prune_pending_entries_for_sample, remove_corpus_from_entry, sample_key, unique_corpora,
};
use super::types::{Error, IndexEntry};
use crate::databases::localdb::{EntityMetadataRecord, normalize_metadata_name};
use crate::indexing::Entity;
use std::collections::BTreeMap;

impl LocalIndex {
    pub fn symbol_add(
        &self,
        sha256: &str,
        collection: crate::indexing::Collection,
        address: u64,
        name: &str,
        username: &str,
    ) -> Result<(), Error> {
        self.mutate_symbol(
            sha256,
            collection,
            address,
            name,
            username,
            super::support::SymbolMutation::Add,
        )
    }

    pub fn symbol_remove(
        &self,
        sha256: &str,
        collection: crate::indexing::Collection,
        address: u64,
        name: &str,
    ) -> Result<(), Error> {
        self.mutate_symbol(
            sha256,
            collection,
            address,
            name,
            "",
            super::support::SymbolMutation::Remove,
        )
    }

    pub fn symbol_replace(
        &self,
        sha256: &str,
        collection: crate::indexing::Collection,
        address: u64,
        name: &str,
        username: &str,
    ) -> Result<(), Error> {
        self.mutate_symbol(
            sha256,
            collection,
            address,
            name,
            username,
            super::support::SymbolMutation::Replace,
        )
    }

    pub fn symbol_delete_global(&self, name: &str) -> Result<(), Error> {
        let name = normalize_metadata_name("symbol", name)
            .map_err(|error| Error::Validation(error.to_string()))?;
        let keys = self
            .store
            .object_list("index/")
            .map_err(|error| Error::LocalStore(error.to_string()))?;
        for key in keys {
            let mut entry = self
                .store
                .object_get_json::<IndexEntry>(&key)
                .map_err(|error| Error::LocalStore(error.to_string()))?;
            let (changed, _) = mutate_symbol_attributes(
                &mut entry.attributes,
                entry.entity,
                entry.address,
                &name,
                "",
                "",
                super::support::SymbolMutation::Remove,
            );
            if changed {
                self.store
                    .object_put_json(&key, &entry)
                    .map_err(|error| Error::LocalStore(error.to_string()))?;
                self.localdb
                    .entity_metadata_upsert(&EntityMetadataRecord {
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
                    })
                    .map_err(|error| Error::LocalDb(error.to_string()))?;
            }
        }
        self.localdb
            .symbol_delete_global(&name)
            .map_err(|error| Error::LocalDb(error.to_string()))?;
        Ok(())
    }

    pub fn collection_corpus_list(
        &self,
        sha256: &str,
        collection: crate::indexing::Collection,
        architecture: &str,
        address: u64,
    ) -> Result<Vec<String>, Error> {
        self.collection_entry(sha256, collection, architecture, address)?;
        self.localdb
            .entity_corpus_list(sha256, collection, architecture, address)
            .map_err(|error| Error::LocalDb(error.to_string()))
    }

    pub fn collection_corpus_details_list(
        &self,
        sha256: &str,
        collection: crate::indexing::Collection,
        architecture: &str,
        address: u64,
    ) -> Result<Vec<crate::databases::localdb::CorpusRecord>, Error> {
        self.collection_entry(sha256, collection, architecture, address)?;
        self.localdb
            .entity_corpus_details_list(sha256, collection, architecture, address)
            .map_err(|error| Error::LocalDb(error.to_string()))
    }

    pub fn collection_corpus_add(
        &self,
        sha256: &str,
        collection: crate::indexing::Collection,
        architecture: &str,
        address: u64,
        corpus: &str,
        username: &str,
    ) -> Result<(), Error> {
        self.mutate_collection_corpus(
            sha256,
            collection,
            architecture,
            address,
            corpus,
            username,
            true,
        )
    }

    pub fn collection_corpus_remove(
        &self,
        sha256: &str,
        collection: crate::indexing::Collection,
        architecture: &str,
        address: u64,
        corpus: &str,
    ) -> Result<(), Error> {
        self.mutate_collection_corpus(sha256, collection, architecture, address, corpus, "", false)
    }

    pub fn corpus_rename(&self, old_name: &str, new_name: &str) -> Result<(), Error> {
        let old_name = old_name.trim();
        let new_name = new_name.trim();
        if old_name.is_empty() || new_name.is_empty() {
            return Err(Error::Validation("corpus must not be empty".to_string()));
        }
        if old_name == new_name {
            return Ok(());
        }

        self.localdb
            .entity_corpus_rename(old_name, new_name)
            .map_err(|error| Error::LocalDb(error.to_string()))?;

        let keys = self
            .store
            .object_list("index/")
            .map_err(|error| Error::LocalStore(error.to_string()))?;
        for key in keys {
            let mut entry = self
                .store
                .object_get_json::<IndexEntry>(&key)
                .map_err(|error| Error::LocalStore(error.to_string()))?;
            let mut changed = false;
            if let Some(explicit) = &mut entry.explicit_corpora {
                for corpus in explicit {
                    if corpus == old_name {
                        *corpus = new_name.to_string();
                        changed = true;
                    }
                }
            }
            if !changed {
                continue;
            }
            if let Some(explicit) = &mut entry.explicit_corpora {
                *explicit = unique_corpora(explicit);
            }
            self.store
                .object_put_json(&key, &entry)
                .map_err(|error| Error::LocalStore(error.to_string()))?;
        }
        Ok(())
    }

    pub fn architecture_list(&self) -> Result<Vec<String>, Error> {
        let keys = self
            .store
            .object_list("index/")
            .map_err(|error| Error::LocalStore(error.to_string()))?;
        let mut architectures = keys
            .into_iter()
            .filter_map(|key| super::support::architecture_from_index_entry_key(&key))
            .collect::<Vec<_>>();
        architectures.sort();
        architectures.dedup();
        Ok(architectures)
    }

    pub fn sample_delete(&self, corpus: &str, sha256: &str) -> Result<(), Error> {
        super::support::validate_corpus_sha256(corpus, sha256)?;
        let mut pending = self.pending.lock().unwrap();
        pending
            .deleted_samples
            .push((corpus.to_string(), sha256.to_string()));
        let (entries, entity_corpora) = {
            let pending = &mut *pending;
            (&mut pending.entries, &mut pending.entity_corpora)
        };
        prune_pending_entries_for_sample(entries, entity_corpora, sha256, corpus);
        Ok(())
    }

    pub fn corpus_delete(&self, corpus: &str) -> Result<(), Error> {
        let corpus = normalize_metadata_name("corpus", corpus)
            .map_err(|error| Error::Validation(error.to_string()))?;
        let mut pending = self.pending.lock().unwrap();
        pending.deleted_corpora.push(corpus.clone());
        let (entries, entity_corpora) = {
            let pending = &mut *pending;
            (&mut pending.entries, &mut pending.entity_corpora)
        };
        prune_pending_entries_for_corpus(entries, entity_corpora, &corpus);
        pending
            .deleted_samples
            .retain(|(existing_corpus, _)| existing_corpus != &corpus);
        Ok(())
    }

    fn mutate_symbol(
        &self,
        sha256: &str,
        collection: crate::indexing::Collection,
        address: u64,
        name: &str,
        username: &str,
        mutation: super::support::SymbolMutation,
    ) -> Result<(), Error> {
        let sha256 = sha256.trim();
        if !is_sha256(sha256) {
            return Err(Error::Validation(format!("invalid sha256 {}", sha256)));
        }
        let name = normalize_metadata_name("symbol", name)
            .map_err(|error| Error::Validation(error.to_string()))?;
        if !self
            .store
            .object_exists(&sample_key(sha256))
            .map_err(|error| Error::LocalStore(error.to_string()))?
        {
            return Err(Error::NotFound(format!("sample {}", sha256)));
        }

        let keys = self
            .store
            .object_list("index/")
            .map_err(|error| Error::LocalStore(error.to_string()))?;
        let target_entity = match collection {
            crate::indexing::Collection::Function => crate::indexing::Entity::Function,
            crate::indexing::Collection::Block => crate::indexing::Entity::Block,
            crate::indexing::Collection::Instruction => crate::indexing::Entity::Instruction,
        };
        let timestamp = chrono::Utc::now().to_rfc3339();
        let mut updated_rows = BTreeMap::<(Entity, String), Vec<local_lancedb::Row>>::new();
        let mut matched_entry = false;
        let mut matched_symbol = false;
        for key in keys {
            let mut entry = self
                .store
                .object_get_json::<IndexEntry>(&key)
                .map_err(|error| Error::LocalStore(error.to_string()))?;
            if entry.sha256 != sha256 || entry.address != address || entry.entity != target_entity {
                continue;
            }
            matched_entry = true;
            let (changed, entry_matched_symbol) = mutate_symbol_attributes(
                &mut entry.attributes,
                entry.entity,
                address,
                &name,
                username,
                &timestamp,
                mutation,
            );
            matched_symbol |= entry_matched_symbol;
            if !changed {
                continue;
            }
            self.store
                .object_put_json(&key, &entry)
                .map_err(|error| Error::LocalStore(error.to_string()))?;
            self.localdb
                .entity_metadata_upsert(&EntityMetadataRecord {
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
                })
                .map_err(|error| Error::LocalDb(error.to_string()))?;
            updated_rows
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

        if !matched_entry {
            return Err(Error::NotFound(format!(
                "indexed address {:#x} for sample {}",
                address, sha256
            )));
        }
        if matches!(mutation, super::support::SymbolMutation::Remove) && !matched_symbol {
            return Err(Error::NotFound(format!(
                "symbol {} at address {:#x} for sample {}",
                name, address, sha256
            )));
        }
        if matches!(
            mutation,
            super::support::SymbolMutation::Add | super::support::SymbolMutation::Replace
        ) {
            self.localdb
                .symbol_add(&name, Some(&timestamp), Some(username))
                .map_err(|error| Error::LocalDb(error.to_string()))?;
        }

        for ((collection, architecture), rows) in updated_rows {
            local_lancedb::upsert_rows(&self.lancedb, collection, &architecture, &rows)
                .map_err(|error| Error::LanceDb(error.to_string()))?;
        }
        Ok(())
    }

    fn collection_entry(
        &self,
        sha256: &str,
        collection: crate::indexing::Collection,
        architecture: &str,
        address: u64,
    ) -> Result<IndexEntry, Error> {
        let sha256 = sha256.trim();
        if !is_sha256(sha256) {
            return Err(Error::Validation(format!("invalid sha256 {}", sha256)));
        }
        let object_id = super::support::manual_object_id(collection, architecture, sha256, address);
        let key = super::support::index_entry_key(collection, architecture, &object_id);
        self.store
            .object_get_json::<IndexEntry>(&key)
            .map_err(|error| match error {
                crate::storage::localstore::Error::NotFound(_) => Error::NotFound(format!(
                    "indexed {}/{:#x} for sample {}",
                    collection.as_str(),
                    address,
                    sha256
                )),
                other => Error::LocalStore(other.to_string()),
            })
    }

    fn mutate_collection_corpus(
        &self,
        sha256: &str,
        collection: crate::indexing::Collection,
        architecture: &str,
        address: u64,
        corpus: &str,
        username: &str,
        add: bool,
    ) -> Result<(), Error> {
        let corpus = normalize_metadata_name("corpus", corpus)
            .map_err(|error| Error::Validation(error.to_string()))?;
        let mut entry = self.collection_entry(sha256, collection, architecture, address)?;
        let mut effective = self
            .localdb
            .entity_corpus_list(sha256, collection, architecture, address)
            .map_err(|error| Error::LocalDb(error.to_string()))?;
        if add {
            effective = normalize_index_corpora(&super::support::union_corpora(
                &effective,
                std::slice::from_ref(&corpus),
            ))?;
        } else {
            effective.retain(|existing| existing != &corpus);
            effective = unique_corpora(&effective);
        }
        entry.username = username.to_string();
        entry.timestamp = chrono::Utc::now().to_rfc3339();
        entry.explicit_corpora = (!effective.is_empty()).then_some(effective);
        let object_id = super::support::manual_object_id(collection, architecture, sha256, address);
        let key = super::support::index_entry_key(collection, architecture, &object_id);
        self.store
            .object_put_json(&key, &entry)
            .map_err(|error| Error::LocalStore(error.to_string()))?;
        self.localdb
            .entity_corpus_replace(
                &entry.sha256,
                entry.entity,
                &entry.architecture,
                entry.address,
                entry.explicit_corpora.as_deref().unwrap_or(&[]),
                &entry.username,
                &entry.timestamp,
            )
            .map_err(|error| Error::LocalDb(error.to_string()))
    }

    pub(super) fn delete_sample_committed(&self, corpus: &str, sha256: &str) -> Result<(), Error> {
        self.localdb
            .entity_corpus_delete_for_sample(sha256, Some(corpus))
            .map_err(|error| Error::LocalDb(error.to_string()))?;
        let keys = self
            .store
            .object_list("index/")
            .map_err(|error| Error::LocalStore(error.to_string()))?;
        for key in keys {
            let mut entry = self
                .store
                .object_get_json::<IndexEntry>(&key)
                .map_err(|error| Error::LocalStore(error.to_string()))?;
            if entry.sha256 != sha256 {
                continue;
            }
            if remove_corpus_from_entry(&mut entry, Some(corpus)) {
                self.store
                    .object_put_json(&key, &entry)
                    .map_err(|error| Error::LocalStore(error.to_string()))?;
            }
        }
        Ok(())
    }

    pub(super) fn delete_corpus_committed(&self, corpus: &str) -> Result<(), Error> {
        self.localdb
            .entity_corpus_delete_global(corpus)
            .map_err(|error| Error::LocalDb(error.to_string()))?;
        let keys = self
            .store
            .object_list("index/")
            .map_err(|error| Error::LocalStore(error.to_string()))?;
        let mut affected_samples = BTreeMap::<String, ()>::new();
        for key in keys {
            let mut entry = self
                .store
                .object_get_json::<IndexEntry>(&key)
                .map_err(|error| Error::LocalStore(error.to_string()))?;
            if remove_corpus_from_entry(&mut entry, Some(corpus)) {
                affected_samples.insert(entry.sha256.clone(), ());
                self.store
                    .object_put_json(&key, &entry)
                    .map_err(|error| Error::LocalStore(error.to_string()))?;
            }
        }
        Ok(())
    }
}
