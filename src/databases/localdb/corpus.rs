use super::*;

impl LocalDB {
    pub fn sample_sha256_search(
        &self,
        query: &str,
        page: usize,
        page_size: usize,
    ) -> Result<crate::databases::localdb::CountedPage<SampleSha256Record>, Error> {
        let page = page.max(1);
        let page_size = page_size.max(1);
        let offset = (page - 1) * page_size;
        let limit = page_size + 1;
        let pattern = if query.trim().is_empty() {
            "%".to_string()
        } else {
            format!("{}%", query.trim().to_ascii_lowercase())
        };
        let total_rows = self.sqlite.query(
            "SELECT COUNT(*) AS count
             FROM (
                SELECT sha256 FROM sample_status
                UNION
                SELECT DISTINCT sha256 FROM entity_metadata
             )
             WHERE LOWER(sha256) LIKE ?1",
            &[SQLiteValue::Text(pattern.clone())],
        )?;
        let total_results = total_rows
            .first()
            .and_then(|row| row.get("count"))
            .and_then(|value| value.as_i64())
            .unwrap_or(0)
            .max(0) as usize;
        let rows = self.sqlite.query(
            "SELECT sha256
             FROM (
                SELECT sha256 FROM sample_status
                UNION
                SELECT DISTINCT sha256 FROM entity_metadata
             )
             WHERE LOWER(sha256) LIKE ?1
             ORDER BY sha256 ASC
             LIMIT ?2 OFFSET ?3",
            &[
                SQLiteValue::Text(pattern),
                SQLiteValue::Integer(limit as i64),
                SQLiteValue::Integer(offset as i64),
            ],
        )?;
        let has_next = rows.len() > page_size;
        let items = rows
            .into_iter()
            .take(page_size)
            .filter_map(|row| {
                row.get("sha256")
                    .and_then(|value| value.as_str())
                    .map(|sha256| SampleSha256Record {
                        sha256: sha256.to_string(),
                    })
            })
            .collect::<Vec<_>>();
        Ok(crate::databases::localdb::CountedPage {
            items,
            page,
            page_size,
            total_results,
            has_next,
        })
    }

    pub fn sample_status_get(&self, sha256: &str) -> Result<Option<SampleStatusRecord>, Error> {
        let rows = self.sqlite.query(
            "SELECT sha256, username, status, timestamp, error_message, id FROM sample_status WHERE sha256 = ?1",
            &[SQLiteValue::Text(sha256.to_string())],
        )?;
        let Some(row) = rows.into_iter().next() else {
            return Ok(None);
        };
        let status = row
            .get("status")
            .and_then(|value| value.as_str())
            .ok_or_else(|| Error("sample status row is missing status".to_string()))
            .and_then(SampleStatus::parse)?;
        Ok(Some(SampleStatusRecord {
            sha256: row
                .get("sha256")
                .and_then(|value| value.as_str())
                .ok_or_else(|| Error("sample status row is missing sha256".to_string()))?
                .to_string(),
            username: row
                .get("username")
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_string(),
            status,
            timestamp: row
                .get("timestamp")
                .and_then(|value| value.as_str())
                .ok_or_else(|| Error("sample status row is missing timestamp".to_string()))?
                .to_string(),
            error_message: row
                .get("error_message")
                .and_then(|value| value.as_str())
                .map(ToString::to_string),
            id: row
                .get("id")
                .and_then(|value| value.as_str())
                .map(ToString::to_string),
        }))
    }

    pub fn sample_origin_get(&self, sha256: &str) -> Result<Option<SampleOriginRecord>, Error> {
        let normalized = sha256.trim().to_string();
        let rows = self.sqlite.query(
            "SELECT sha256, username, timestamp
             FROM entity_metadata
             WHERE sha256 = ?1
             ORDER BY timestamp ASC, address ASC
             LIMIT 1",
            &[SQLiteValue::Text(normalized.clone())],
        )?;
        if let Some(row) = rows.into_iter().next() {
            return Ok(Some(SampleOriginRecord {
                sha256: row
                    .get("sha256")
                    .and_then(|value| value.as_str())
                    .unwrap_or_default()
                    .to_string(),
                username: row
                    .get("username")
                    .and_then(|value| value.as_str())
                    .unwrap_or_default()
                    .to_string(),
                timestamp: row
                    .get("timestamp")
                    .and_then(|value| value.as_str())
                    .unwrap_or_default()
                    .to_string(),
            }));
        }
        self.sample_status_get(&normalized).map(|record| {
            record.map(|item| SampleOriginRecord {
                sha256: item.sha256,
                username: item.username,
                timestamp: item.timestamp,
            })
        })
    }

    pub fn sample_status_set(&self, status: &SampleStatusRecord) -> Result<(), Error> {
        self.sqlite.execute(
            "INSERT INTO sample_status (sha256, username, status, timestamp, error_message, id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(sha256) DO UPDATE SET
               username = excluded.username,
               status = excluded.status,
               timestamp = excluded.timestamp,
               error_message = excluded.error_message,
               id = excluded.id",
            &[
                SQLiteValue::Text(status.sha256.clone()),
                SQLiteValue::Text(status.username.clone()),
                SQLiteValue::Text(status.status.as_str().to_string()),
                SQLiteValue::Text(status.timestamp.clone()),
                status
                    .error_message
                    .clone()
                    .map(SQLiteValue::Text)
                    .unwrap_or(SQLiteValue::Null),
                status
                    .id
                    .clone()
                    .map(SQLiteValue::Text)
                    .unwrap_or(SQLiteValue::Null),
            ],
        )?;
        Ok(())
    }

    pub fn sample_status_delete(&self, sha256: &str) -> Result<(), Error> {
        self.sqlite.execute(
            "DELETE FROM sample_status WHERE sha256 = ?1",
            &[SQLiteValue::Text(sha256.to_string())],
        )?;
        Ok(())
    }

    pub fn corpus_add(
        &self,
        corpus: &str,
        timestamp: Option<&str>,
        username: Option<&str>,
    ) -> Result<(), Error> {
        let corpus = normalize_metadata_name("corpus", corpus)?;
        let timestamp = timestamp
            .map(ToString::to_string)
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
        let username = username.unwrap_or_default().trim().to_string();
        self.sqlite.execute(
            "INSERT INTO corpora_catalog (corpus, username, timestamp)
             VALUES (?1, ?2, ?3)
            ON CONFLICT(corpus) DO UPDATE SET
              username = excluded.username,
              timestamp = excluded.timestamp",
            &[
                SQLiteValue::Text(corpus),
                SQLiteValue::Text(username),
                SQLiteValue::Text(timestamp),
            ],
        )?;
        Ok(())
    }

    pub fn corpus_search(&self, query: &str, limit: usize) -> Result<Vec<String>, Error> {
        self.corpus_search_details(query, limit)
            .map(|items| items.into_iter().map(|item| item.corpus).collect())
    }

    pub fn corpus_search_details(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<Vec<CorpusRecord>, Error> {
        let limit = limit.max(1);
        let pattern = if query.trim().is_empty() {
            "%".to_string()
        } else {
            format!("%{}%", query.trim().to_ascii_lowercase())
        };
        let rows = self.sqlite.query(
            "SELECT corpus, username, timestamp
             FROM corpora_catalog
             WHERE LOWER(corpus) LIKE ?1
             ORDER BY corpus ASC
             LIMIT ?2",
            &[
                SQLiteValue::Text(pattern),
                SQLiteValue::Integer(limit as i64),
            ],
        )?;
        rows.into_iter()
            .map(|row| {
                Ok(CorpusRecord {
                    corpus: row
                        .get("corpus")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| Error("corpus row is missing corpus".to_string()))?
                        .to_string(),
                    username: row
                        .get("username")
                        .and_then(|value| value.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    timestamp: row
                        .get("timestamp")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| Error("corpus row is missing timestamp".to_string()))?
                        .to_string(),
                })
            })
            .collect()
    }

    pub fn corpus_get(&self, corpus: &str) -> Result<Option<CorpusRecord>, Error> {
        let rows = self.sqlite.query(
            "SELECT corpus, username, timestamp
             FROM corpora_catalog
             WHERE corpus = ?1
             LIMIT 1",
            &[SQLiteValue::Text(corpus.trim().to_string())],
        )?;
        rows.into_iter()
            .next()
            .map(|row| {
                Ok(CorpusRecord {
                    corpus: row
                        .get("corpus")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| Error("corpus row is missing corpus".to_string()))?
                        .to_string(),
                    username: row
                        .get("username")
                        .and_then(|value| value.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    timestamp: row
                        .get("timestamp")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| Error("corpus row is missing timestamp".to_string()))?
                        .to_string(),
                })
            })
            .transpose()
    }

    pub fn corpus_delete_global(&self, corpus: &str) -> Result<bool, Error> {
        let corpus = normalize_metadata_name("corpus", corpus)?;
        if matches!(
            corpus.to_ascii_lowercase().as_str(),
            "default" | "goodware" | "malware"
        ) {
            return Err(Error(format!("core corpus {} cannot be deleted", corpus)));
        }
        self.sqlite.execute(
            "DELETE FROM corpora_catalog WHERE corpus = ?1",
            &[SQLiteValue::Text(corpus.clone())],
        )?;
        self.entity_corpus_delete_global(&corpus)?;
        let rows = self.sqlite.query(
            "SELECT corpus FROM corpora_catalog WHERE corpus = ?1 LIMIT 1",
            &[SQLiteValue::Text(corpus)],
        )?;
        Ok(rows.is_empty())
    }

    pub fn entity_corpus_replace(
        &self,
        sha256: &str,
        collection: Collection,
        architecture: &str,
        address: u64,
        corpora: &[String],
        username: &str,
        timestamp: &str,
    ) -> Result<(), Error> {
        self.sqlite.execute(
            "DELETE FROM entity_corpora
             WHERE sha256 = ?1 AND collection = ?2 AND architecture = ?3 AND address = ?4",
            &[
                SQLiteValue::Text(sha256.to_string()),
                SQLiteValue::Text(collection.as_str().to_string()),
                SQLiteValue::Text(architecture.to_string()),
                SQLiteValue::Integer(address as i64),
            ],
        )?;
        for corpus in corpora {
            let corpus = normalize_metadata_name("corpus", corpus)?;
            self.sqlite.execute(
                "INSERT INTO entity_corpora (sha256, collection, architecture, address, corpus, username, timestamp)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(sha256, collection, architecture, address, corpus) DO UPDATE SET
                   username = excluded.username,
                   timestamp = excluded.timestamp",
                &[
                    SQLiteValue::Text(sha256.to_string()),
                    SQLiteValue::Text(collection.as_str().to_string()),
                    SQLiteValue::Text(architecture.to_string()),
                    SQLiteValue::Integer(address as i64),
                    SQLiteValue::Text(corpus),
                    SQLiteValue::Text(username.to_string()),
                    SQLiteValue::Text(timestamp.to_string()),
                ],
            )?;
        }
        Ok(())
    }

    pub fn entity_corpus_list(
        &self,
        sha256: &str,
        collection: Collection,
        architecture: &str,
        address: u64,
    ) -> Result<Vec<String>, Error> {
        self.entity_corpus_details_list(sha256, collection, architecture, address)
            .map(|items| items.into_iter().map(|item| item.corpus).collect())
    }

    pub fn entity_corpus_details_list(
        &self,
        sha256: &str,
        collection: Collection,
        architecture: &str,
        address: u64,
    ) -> Result<Vec<CorpusRecord>, Error> {
        let rows = self.sqlite.query(
            "SELECT corpus, username, timestamp
             FROM entity_corpora
             WHERE sha256 = ?1 AND collection = ?2 AND architecture = ?3 AND address = ?4
             ORDER BY corpus ASC",
            &[
                SQLiteValue::Text(sha256.to_string()),
                SQLiteValue::Text(collection.as_str().to_string()),
                SQLiteValue::Text(architecture.to_string()),
                SQLiteValue::Integer(address as i64),
            ],
        )?;
        rows.into_iter()
            .map(|row| {
                Ok(CorpusRecord {
                    corpus: row
                        .get("corpus")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| Error("entity corpus row is missing corpus".to_string()))?
                        .to_string(),
                    username: row
                        .get("username")
                        .and_then(|value| value.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    timestamp: row
                        .get("timestamp")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| Error("entity corpus row is missing timestamp".to_string()))?
                        .to_string(),
                })
            })
            .collect()
    }

    pub fn entity_corpus_details_page(
        &self,
        sha256: &str,
        collection: Collection,
        architecture: &str,
        address: u64,
        page: usize,
        page_size: usize,
    ) -> Result<crate::databases::localdb::CountedPage<CorpusRecord>, Error> {
        let page = page.max(1);
        let page_size = page_size.max(1);
        let offset = (page - 1) * page_size;
        let limit = page_size + 1;
        let total_rows = self.sqlite.query(
            "SELECT COUNT(*) AS count
             FROM entity_corpora
             WHERE sha256 = ?1 AND collection = ?2 AND architecture = ?3 AND address = ?4",
            &[
                SQLiteValue::Text(sha256.to_string()),
                SQLiteValue::Text(collection.as_str().to_string()),
                SQLiteValue::Text(architecture.to_string()),
                SQLiteValue::Integer(address as i64),
            ],
        )?;
        let total_results = total_rows
            .first()
            .and_then(|row| row.get("count"))
            .and_then(|value| value.as_i64())
            .unwrap_or(0)
            .max(0) as usize;
        let rows = self.sqlite.query(
            "SELECT corpus, username, timestamp
             FROM entity_corpora
             WHERE sha256 = ?1 AND collection = ?2 AND architecture = ?3 AND address = ?4
             ORDER BY corpus ASC
             LIMIT ?5 OFFSET ?6",
            &[
                SQLiteValue::Text(sha256.to_string()),
                SQLiteValue::Text(collection.as_str().to_string()),
                SQLiteValue::Text(architecture.to_string()),
                SQLiteValue::Integer(address as i64),
                SQLiteValue::Integer(limit as i64),
                SQLiteValue::Integer(offset as i64),
            ],
        )?;
        let has_next = rows.len() > page_size;
        let items = rows
            .into_iter()
            .take(page_size)
            .map(|row| -> Result<CorpusRecord, Error> {
                Ok(CorpusRecord {
                    corpus: row
                        .get("corpus")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| Error("entity corpus row is missing corpus".to_string()))?
                        .to_string(),
                    username: row
                        .get("username")
                        .and_then(|value| value.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    timestamp: row
                        .get("timestamp")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| Error("entity corpus row is missing timestamp".to_string()))?
                        .to_string(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(crate::databases::localdb::CountedPage {
            items,
            page,
            page_size,
            total_results,
            has_next,
        })
    }

    pub fn entity_corpus_has_any(
        &self,
        sha256: &str,
        collection: Collection,
        architecture: &str,
        address: u64,
        corpora: &[String],
    ) -> Result<bool, Error> {
        if corpora.is_empty() {
            return Ok(false);
        }
        let placeholders = (0..corpora.len())
            .map(|index| format!("?{}", index + 5))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "SELECT 1
             FROM entity_corpora
             WHERE sha256 = ?1 AND collection = ?2 AND architecture = ?3 AND address = ?4
               AND corpus IN ({})
             LIMIT 1",
            placeholders
        );
        let mut params = vec![
            SQLiteValue::Text(sha256.to_string()),
            SQLiteValue::Text(collection.as_str().to_string()),
            SQLiteValue::Text(architecture.to_string()),
            SQLiteValue::Integer(address as i64),
        ];
        params.extend(
            corpora
                .iter()
                .map(|corpus| SQLiteValue::Text(corpus.to_string())),
        );
        let rows = self.sqlite.query(&sql, &params)?;
        Ok(!rows.is_empty())
    }

    pub fn entity_corpus_exists_for_sample(
        &self,
        sha256: &str,
        corpus: &str,
    ) -> Result<bool, Error> {
        let rows = self.sqlite.query(
            "SELECT 1
             FROM entity_corpora
             WHERE sha256 = ?1 AND corpus = ?2
             LIMIT 1",
            &[
                SQLiteValue::Text(sha256.to_string()),
                SQLiteValue::Text(corpus.to_string()),
            ],
        )?;
        Ok(!rows.is_empty())
    }

    pub fn entity_corpus_distinct(&self) -> Result<Vec<String>, Error> {
        let rows = self.sqlite.query(
            "SELECT DISTINCT corpus
             FROM entity_corpora
             ORDER BY corpus ASC",
            &[],
        )?;
        rows.into_iter()
            .map(|row| {
                row.get("corpus")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| Error("entity corpus row is missing corpus".to_string()))
                    .map(ToString::to_string)
            })
            .collect()
    }

    pub fn entity_corpus_refs_for_any(
        &self,
        corpora: &[String],
    ) -> Result<Vec<EntityCorpusRef>, Error> {
        if corpora.is_empty() {
            return Ok(Vec::new());
        }
        let placeholders = (0..corpora.len())
            .map(|index| format!("?{}", index + 1))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "SELECT DISTINCT sha256, collection, architecture, address
             FROM entity_corpora
             WHERE corpus IN ({})
             ORDER BY sha256, collection, architecture, address",
            placeholders
        );
        let params = corpora
            .iter()
            .map(|corpus| SQLiteValue::Text(corpus.to_string()))
            .collect::<Vec<_>>();
        let rows = self.sqlite.query(&sql, &params)?;
        rows.into_iter()
            .map(|row| {
                let collection = match row
                    .get("collection")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| Error("entity corpus row is missing collection".to_string()))?
                {
                    "instructions" => Collection::Instruction,
                    "blocks" => Collection::Block,
                    "functions" => Collection::Function,
                    value => {
                        return Err(Error(format!(
                            "entity corpus row contains invalid collection {}",
                            value
                        )));
                    }
                };
                let address = row
                    .get("address")
                    .and_then(|value| value.as_i64())
                    .ok_or_else(|| Error("entity corpus row is missing address".to_string()))?;
                Ok(EntityCorpusRef {
                    sha256: row
                        .get("sha256")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| Error("entity corpus row is missing sha256".to_string()))?
                        .to_string(),
                    collection,
                    architecture: row
                        .get("architecture")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| {
                            Error("entity corpus row is missing architecture".to_string())
                        })?
                        .to_string(),
                    address: address as u64,
                })
            })
            .collect()
    }

    pub fn entity_corpus_rename(&self, old_name: &str, new_name: &str) -> Result<(), Error> {
        let old_name = normalize_metadata_name("corpus", old_name)?;
        let new_name = normalize_metadata_name("corpus", new_name)?;
        self.sqlite.execute(
            "UPDATE entity_corpora SET corpus = ?2 WHERE corpus = ?1",
            &[SQLiteValue::Text(old_name), SQLiteValue::Text(new_name)],
        )?;
        self.sqlite.execute(
            "DELETE FROM entity_corpora
             WHERE rowid NOT IN (
                 SELECT MIN(rowid)
                 FROM entity_corpora
                 GROUP BY sha256, collection, architecture, address, corpus
             )",
            &[],
        )?;
        Ok(())
    }

    pub fn embedding_count_get(
        &self,
        collection: Collection,
        architecture: &str,
        embedding: &str,
    ) -> Result<u64, Error> {
        let rows = self.sqlite.query(
            "SELECT count
             FROM embedding_counts
             WHERE collection = ?1 AND architecture = ?2 AND embedding = ?3
             LIMIT 1",
            &[
                SQLiteValue::Text(collection.as_str().to_string()),
                SQLiteValue::Text(architecture.to_string()),
                SQLiteValue::Text(embedding.to_string()),
            ],
        )?;
        let Some(row) = rows.into_iter().next() else {
            return Ok(0);
        };
        Ok(row
            .get("count")
            .and_then(|value| value.as_i64())
            .ok_or_else(|| Error("embedding count row is missing count".to_string()))?
            as u64)
    }

    pub fn embedding_count_increment(
        &self,
        collection: Collection,
        architecture: &str,
        embedding: &str,
        delta: u64,
    ) -> Result<(), Error> {
        if delta == 0 {
            return Ok(());
        }
        self.sqlite.execute(
            "INSERT INTO embedding_counts (collection, architecture, embedding, count)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(collection, architecture, embedding) DO UPDATE SET
               count = embedding_counts.count + excluded.count",
            &[
                SQLiteValue::Text(collection.as_str().to_string()),
                SQLiteValue::Text(architecture.to_string()),
                SQLiteValue::Text(embedding.to_string()),
                SQLiteValue::Integer(delta as i64),
            ],
        )?;
        Ok(())
    }

    pub fn embedding_count_decrement(
        &self,
        collection: Collection,
        architecture: &str,
        embedding: &str,
        delta: u64,
    ) -> Result<(), Error> {
        if delta == 0 {
            return Ok(());
        }
        let current = self.embedding_count_get(collection, architecture, embedding)?;
        if current <= delta {
            self.sqlite.execute(
                "DELETE FROM embedding_counts
                 WHERE collection = ?1 AND architecture = ?2 AND embedding = ?3",
                &[
                    SQLiteValue::Text(collection.as_str().to_string()),
                    SQLiteValue::Text(architecture.to_string()),
                    SQLiteValue::Text(embedding.to_string()),
                ],
            )?;
            return Ok(());
        }
        self.sqlite.execute(
            "UPDATE embedding_counts
             SET count = count - ?4
             WHERE collection = ?1 AND architecture = ?2 AND embedding = ?3",
            &[
                SQLiteValue::Text(collection.as_str().to_string()),
                SQLiteValue::Text(architecture.to_string()),
                SQLiteValue::Text(embedding.to_string()),
                SQLiteValue::Integer(delta as i64),
            ],
        )?;
        Ok(())
    }

    pub fn embedding_count_clear(&self) -> Result<(), Error> {
        self.sqlite.execute("DELETE FROM embedding_counts", &[])?;
        Ok(())
    }

    pub fn apply_index_commit(
        &self,
        entity_corpora: &[EntityCorpusWrite],
        entity_children: &[EntityChildWrite],
        metadata: &[EntityMetadataRecord],
        embedding_deltas: &[EmbeddingCountDelta],
    ) -> Result<(), Error> {
        let mut connection = self.sqlite.connection()?;
        let transaction = connection.transaction()?;

        {
            let mut embedding_upsert = transaction.prepare(
                "INSERT INTO embedding_counts (collection, architecture, embedding, count)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(collection, architecture, embedding) DO UPDATE SET
                   count = count + excluded.count",
            )?;
            let mut embedding_prune =
                transaction.prepare("DELETE FROM embedding_counts WHERE count <= 0")?;
            for delta in embedding_deltas {
                if delta.delta == 0 {
                    continue;
                }
                embedding_upsert.execute((
                    delta.collection.as_str(),
                    &delta.architecture,
                    &delta.embedding,
                    delta.delta,
                ))?;
            }
            embedding_prune.execute([])?;
        }

        {
            let mut entity_delete = transaction.prepare(
                "DELETE FROM entity_corpora
                 WHERE sha256 = ?1 AND collection = ?2 AND architecture = ?3 AND address = ?4",
            )?;
            let mut entity_insert = transaction.prepare(
                "INSERT INTO entity_corpora (sha256, collection, architecture, address, corpus, username, timestamp)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(sha256, collection, architecture, address, corpus) DO UPDATE SET
                   username = excluded.username,
                   timestamp = excluded.timestamp",
            )?;
            for write in entity_corpora {
                entity_delete.execute((
                    &write.sha256,
                    write.collection.as_str(),
                    &write.architecture,
                    write.address as i64,
                ))?;
                for corpus in &write.corpora {
                    let corpus = normalize_metadata_name("corpus", corpus)?;
                    entity_insert.execute((
                        &write.sha256,
                        write.collection.as_str(),
                        &write.architecture,
                        write.address as i64,
                        &corpus,
                        &write.username,
                        &write.timestamp,
                    ))?;
                }
            }
        }

        {
            let mut child_delete = transaction.prepare(
                "DELETE FROM entity_children
                 WHERE sha256 = ?1 AND architecture = ?2 AND parent_collection = ?3
                   AND parent_address = ?4 AND child_collection = ?5",
            )?;
            let mut child_insert = transaction.prepare(
                "INSERT INTO entity_children (
                    sha256, architecture, parent_collection, parent_address, child_collection, child_address
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(sha256, architecture, parent_collection, parent_address, child_collection, child_address) DO NOTHING",
            )?;
            for write in entity_children {
                child_delete.execute((
                    &write.sha256,
                    &write.architecture,
                    write.parent_collection.as_str(),
                    write.parent_address as i64,
                    write.child_collection.as_str(),
                ))?;
                for child_address in &write.child_addresses {
                    child_insert.execute((
                        &write.sha256,
                        &write.architecture,
                        write.parent_collection.as_str(),
                        write.parent_address as i64,
                        write.child_collection.as_str(),
                        *child_address as i64,
                    ))?;
                }
            }
        }

        {
            let mut metadata_upsert = transaction.prepare(
                "INSERT INTO entity_metadata (
                    object_id, sha256, collection, architecture, username, address, size,
                    cyclomatic_complexity, average_instructions_per_block, number_of_instructions,
                    number_of_blocks, markov, entropy, contiguous, chromosome_entropy,
                    collection_tag_count, collection_comment_count, timestamp, vector_json, attributes_json
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)
                ON CONFLICT(collection, architecture, object_id) DO UPDATE SET
                    sha256 = excluded.sha256,
                    username = excluded.username,
                    address = excluded.address,
                    size = excluded.size,
                    cyclomatic_complexity = excluded.cyclomatic_complexity,
                    average_instructions_per_block = excluded.average_instructions_per_block,
                    number_of_instructions = excluded.number_of_instructions,
                    number_of_blocks = excluded.number_of_blocks,
                    markov = excluded.markov,
                    entropy = excluded.entropy,
                    contiguous = excluded.contiguous,
                    chromosome_entropy = excluded.chromosome_entropy,
                    collection_tag_count = excluded.collection_tag_count,
                    collection_comment_count = excluded.collection_comment_count,
                    timestamp = excluded.timestamp,
                    vector_json = excluded.vector_json,
                    attributes_json = excluded.attributes_json",
            )?;
            let mut entity_symbol_delete = transaction.prepare(
                "DELETE FROM entity_symbols
                 WHERE sha256 = ?1 AND collection = ?2 AND architecture = ?3 AND address = ?4",
            )?;
            let mut entity_symbol_insert = transaction.prepare(
                "INSERT INTO entity_symbols (
                    sha256, collection, architecture, address, symbol, username, timestamp
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )?;
            for record in metadata {
                let vector = serde_json::to_string(&record.vector)
                    .map_err(|error| Error(error.to_string()))?;
                let attributes = serde_json::to_string(&record.attributes)
                    .map_err(|error| Error(error.to_string()))?;
                let params = vec![
                    SQLiteValue::Text(record.object_id.clone()),
                    SQLiteValue::Text(record.sha256.clone()),
                    SQLiteValue::Text(record.collection.as_str().to_string()),
                    SQLiteValue::Text(record.architecture.clone()),
                    SQLiteValue::Text(record.username.clone()),
                    SQLiteValue::Integer(record.address as i64),
                    SQLiteValue::Integer(record.size as i64),
                    record
                        .cyclomatic_complexity
                        .map(|value| SQLiteValue::Integer(value as i64))
                        .unwrap_or(SQLiteValue::Null),
                    record
                        .average_instructions_per_block
                        .map(SQLiteValue::Real)
                        .unwrap_or(SQLiteValue::Null),
                    record
                        .number_of_instructions
                        .map(|value| SQLiteValue::Integer(value as i64))
                        .unwrap_or(SQLiteValue::Null),
                    record
                        .number_of_blocks
                        .map(|value| SQLiteValue::Integer(value as i64))
                        .unwrap_or(SQLiteValue::Null),
                    record
                        .markov
                        .map(SQLiteValue::Real)
                        .unwrap_or(SQLiteValue::Null),
                    record
                        .entropy
                        .map(SQLiteValue::Real)
                        .unwrap_or(SQLiteValue::Null),
                    record
                        .contiguous
                        .map(|value| SQLiteValue::Integer(if value { 1 } else { 0 }))
                        .unwrap_or(SQLiteValue::Null),
                    record
                        .chromosome_entropy
                        .map(SQLiteValue::Real)
                        .unwrap_or(SQLiteValue::Null),
                    SQLiteValue::Integer(record.collection_tag_count as i64),
                    SQLiteValue::Integer(record.collection_comment_count as i64),
                    SQLiteValue::Text(record.timestamp.clone()),
                    SQLiteValue::Text(vector),
                    SQLiteValue::Text(attributes),
                ];
                metadata_upsert.execute(params_from_iter(params.iter()))?;
                entity_symbol_delete.execute((
                    &record.sha256,
                    record.collection.as_str(),
                    &record.architecture,
                    record.address as i64,
                ))?;
                for item in entity_symbol_records_from_attributes(
                    &record.sha256,
                    record.collection,
                    &record.architecture,
                    record.address,
                    &record.attributes,
                ) {
                    entity_symbol_insert.execute((
                        &item.sha256,
                        item.collection.as_str(),
                        &item.architecture,
                        item.address as i64,
                        &item.symbol,
                        &item.username,
                        &item.timestamp,
                    ))?;
                }
            }
        }

        transaction.commit()?;
        Ok(())
    }

    pub fn entity_metadata_upsert(&self, record: &EntityMetadataRecord) -> Result<(), Error> {
        let vector =
            serde_json::to_string(&record.vector).map_err(|error| Error(error.to_string()))?;
        let collection_tags = serde_json::to_string(&record.collection_tags)
            .map_err(|error| Error(error.to_string()))?;
        let attributes =
            serde_json::to_string(&record.attributes).map_err(|error| Error(error.to_string()))?;
        self.sqlite.execute(
            "INSERT INTO entity_metadata (
                object_id, sha256, collection, architecture, username, address, size,
                cyclomatic_complexity, average_instructions_per_block, number_of_instructions,
                number_of_blocks, markov, entropy, contiguous, chromosome_entropy,
                collection_tag_count, collection_tags_json, collection_comment_count, timestamp, vector_json, attributes_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21)
            ON CONFLICT(collection, architecture, object_id) DO UPDATE SET
                sha256 = excluded.sha256,
                username = excluded.username,
                address = excluded.address,
                size = excluded.size,
                cyclomatic_complexity = excluded.cyclomatic_complexity,
                average_instructions_per_block = excluded.average_instructions_per_block,
                number_of_instructions = excluded.number_of_instructions,
                number_of_blocks = excluded.number_of_blocks,
                markov = excluded.markov,
                entropy = excluded.entropy,
                contiguous = excluded.contiguous,
                chromosome_entropy = excluded.chromosome_entropy,
                collection_tag_count = excluded.collection_tag_count,
                collection_tags_json = excluded.collection_tags_json,
                collection_comment_count = excluded.collection_comment_count,
                timestamp = excluded.timestamp,
                vector_json = excluded.vector_json,
                attributes_json = excluded.attributes_json",
            &[
                SQLiteValue::Text(record.object_id.clone()),
                SQLiteValue::Text(record.sha256.clone()),
                SQLiteValue::Text(record.collection.as_str().to_string()),
                SQLiteValue::Text(record.architecture.clone()),
                SQLiteValue::Text(record.username.clone()),
                SQLiteValue::Integer(record.address as i64),
                SQLiteValue::Integer(record.size as i64),
                record
                    .cyclomatic_complexity
                    .map(|value| SQLiteValue::Integer(value as i64))
                    .unwrap_or(SQLiteValue::Null),
                record
                    .average_instructions_per_block
                    .map(SQLiteValue::Real)
                    .unwrap_or(SQLiteValue::Null),
                record
                    .number_of_instructions
                    .map(|value| SQLiteValue::Integer(value as i64))
                    .unwrap_or(SQLiteValue::Null),
                record
                    .number_of_blocks
                    .map(|value| SQLiteValue::Integer(value as i64))
                    .unwrap_or(SQLiteValue::Null),
                record.markov.map(SQLiteValue::Real).unwrap_or(SQLiteValue::Null),
                record
                    .entropy
                    .map(SQLiteValue::Real)
                    .unwrap_or(SQLiteValue::Null),
                record
                    .contiguous
                    .map(|value| SQLiteValue::Integer(if value { 1 } else { 0 }))
                    .unwrap_or(SQLiteValue::Null),
                record
                    .chromosome_entropy
                    .map(SQLiteValue::Real)
                    .unwrap_or(SQLiteValue::Null),
                SQLiteValue::Integer(record.collection_tag_count as i64),
                SQLiteValue::Text(collection_tags),
                SQLiteValue::Integer(record.collection_comment_count as i64),
                SQLiteValue::Text(record.timestamp.clone()),
                SQLiteValue::Text(vector),
                SQLiteValue::Text(attributes),
            ],
        )?;
        self.entity_symbol_replace_all(
            &record.sha256,
            record.collection,
            &record.architecture,
            record.address,
            &entity_symbol_records_from_attributes(
                &record.sha256,
                record.collection,
                &record.architecture,
                record.address,
                &record.attributes,
            ),
        )?;
        Ok(())
    }

    pub fn entity_metadata_comment_count_set(
        &self,
        sha256: &str,
        collection: Collection,
        address: u64,
        count: u64,
    ) -> Result<(), Error> {
        self.sqlite.execute(
            "UPDATE entity_metadata
             SET collection_comment_count = ?1
             WHERE sha256 = ?2 AND collection = ?3 AND address = ?4",
            &[
                SQLiteValue::Integer(count as i64),
                SQLiteValue::Text(sha256.to_string()),
                SQLiteValue::Text(collection.as_str().to_string()),
                SQLiteValue::Integer(address as i64),
            ],
        )?;
        Ok(())
    }

    pub fn entity_metadata_tag_count_set(
        &self,
        sha256: &str,
        collection: Collection,
        address: u64,
        count: u64,
    ) -> Result<(), Error> {
        self.sqlite.execute(
            "UPDATE entity_metadata
             SET collection_tag_count = ?1
             WHERE sha256 = ?2 AND collection = ?3 AND address = ?4",
            &[
                SQLiteValue::Integer(count as i64),
                SQLiteValue::Text(sha256.to_string()),
                SQLiteValue::Text(collection.as_str().to_string()),
                SQLiteValue::Integer(address as i64),
            ],
        )?;
        Ok(())
    }

    pub fn entity_metadata_tags_set(
        &self,
        sha256: &str,
        collection: Collection,
        address: u64,
        count: u64,
        tags: &[String],
    ) -> Result<(), Error> {
        let collection_tags =
            serde_json::to_string(tags).map_err(|error| Error(error.to_string()))?;
        self.sqlite.execute(
            "UPDATE entity_metadata
             SET collection_tag_count = ?1,
                 collection_tags_json = ?2
             WHERE sha256 = ?3 AND collection = ?4 AND address = ?5",
            &[
                SQLiteValue::Integer(count as i64),
                SQLiteValue::Text(collection_tags),
                SQLiteValue::Text(sha256.to_string()),
                SQLiteValue::Text(collection.as_str().to_string()),
                SQLiteValue::Integer(address as i64),
            ],
        )?;
        Ok(())
    }

    pub fn entity_metadata_get(
        &self,
        collection: Collection,
        architecture: &str,
        object_id: &str,
    ) -> Result<Option<EntityMetadataRecord>, Error> {
        let rows = self.sqlite.query(
            "SELECT object_id, sha256, collection, architecture, username, address, size,
                    cyclomatic_complexity, average_instructions_per_block, number_of_instructions,
                    number_of_blocks, markov, entropy, contiguous, chromosome_entropy,
                    collection_tag_count, collection_tags_json, collection_comment_count, timestamp, vector_json, attributes_json
             FROM entity_metadata
             WHERE collection = ?1 AND architecture = ?2 AND object_id = ?3
             LIMIT 1",
            &[
                SQLiteValue::Text(collection.as_str().to_string()),
                SQLiteValue::Text(architecture.to_string()),
                SQLiteValue::Text(object_id.to_string()),
            ],
        )?;
        rows.into_iter()
            .next()
            .map(entity_metadata_from_row)
            .transpose()
    }

    pub fn entity_metadata_search(
        &self,
        sha256: Option<&str>,
        collections: &[Collection],
        architectures: &[String],
    ) -> Result<Vec<EntityMetadataRecord>, Error> {
        let rows = self.sqlite.query(
            "SELECT object_id, sha256, collection, architecture, username, address, size,
                    cyclomatic_complexity, average_instructions_per_block, number_of_instructions,
                    number_of_blocks, markov, entropy, contiguous, chromosome_entropy,
                    collection_tag_count, collection_tags_json, collection_comment_count, timestamp, vector_json, attributes_json
             FROM entity_metadata
             ORDER BY collection ASC, architecture ASC, sha256 ASC, address ASC",
            &[],
        )?;
        let collection_filter = collections
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        let architecture_filter = architectures
            .iter()
            .map(|value| value.to_ascii_lowercase())
            .collect::<std::collections::BTreeSet<_>>();
        let items = rows
            .into_iter()
            .map(entity_metadata_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(items
            .into_iter()
            .filter(|item| sha256.is_none_or(|value| item.sha256 == value))
            .filter(|item| {
                collection_filter.is_empty() || collection_filter.contains(&item.collection)
            })
            .filter(|item| {
                architecture_filter.is_empty()
                    || architecture_filter.contains(&item.architecture.to_ascii_lowercase())
            })
            .collect())
    }

    pub fn entity_corpus_delete_for_sample(
        &self,
        sha256: &str,
        corpus: Option<&str>,
    ) -> Result<(), Error> {
        match corpus {
            Some(corpus) => self.sqlite.execute(
                "DELETE FROM entity_corpora WHERE sha256 = ?1 AND corpus = ?2",
                &[
                    SQLiteValue::Text(sha256.to_string()),
                    SQLiteValue::Text(corpus.to_string()),
                ],
            )?,
            None => self.sqlite.execute(
                "DELETE FROM entity_corpora WHERE sha256 = ?1",
                &[SQLiteValue::Text(sha256.to_string())],
            )?,
        };
        Ok(())
    }

    pub fn entity_corpus_delete_global(&self, corpus: &str) -> Result<(), Error> {
        self.sqlite.execute(
            "DELETE FROM entity_corpora WHERE corpus = ?1",
            &[SQLiteValue::Text(corpus.to_string())],
        )?;
        Ok(())
    }

    pub fn entity_child_addresses(
        &self,
        sha256: &str,
        architecture: &str,
        parent_collection: Collection,
        parent_address: u64,
        child_collection: Collection,
    ) -> Result<Vec<u64>, Error> {
        let rows = self.sqlite.query(
            "SELECT child_address
             FROM entity_children
             WHERE sha256 = ?1
               AND architecture = ?2
               AND parent_collection = ?3
               AND parent_address = ?4
               AND child_collection = ?5
             ORDER BY child_address ASC",
            &[
                SQLiteValue::Text(sha256.to_string()),
                SQLiteValue::Text(architecture.to_string()),
                SQLiteValue::Text(parent_collection.as_str().to_string()),
                SQLiteValue::Integer(parent_address as i64),
                SQLiteValue::Text(child_collection.as_str().to_string()),
            ],
        )?;
        rows.into_iter()
            .map(|row| {
                row.get("child_address")
                    .and_then(|value| value.as_i64())
                    .map(|value| value as u64)
                    .ok_or_else(|| Error("entity child row is missing child_address".to_string()))
            })
            .collect()
    }
}
