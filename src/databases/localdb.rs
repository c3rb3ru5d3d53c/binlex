use crate::Config;
use crate::databases::sqlite::{Error as SQLiteError, SQLite, SQLiteValue};
use crate::indexing::Collection;
use rand::RngCore;
use ring::digest::{SHA256, digest};
use rusqlite::params_from_iter;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

#[derive(Debug)]
pub struct Error(String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl From<rusqlite::Error> for Error {
    fn from(value: rusqlite::Error) -> Self {
        Self(value.to_string())
    }
}

impl From<SQLiteError> for Error {
    fn from(value: SQLiteError) -> Self {
        Self(value.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SampleStatus {
    Pending,
    Processing,
    Complete,
    Failed,
    Canceled,
}

impl SampleStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Processing => "processing",
            Self::Complete => "complete",
            Self::Failed => "failed",
            Self::Canceled => "canceled",
        }
    }

    fn parse(value: &str) -> Result<Self, Error> {
        match value.trim().to_ascii_lowercase().as_str() {
            "pending" => Ok(Self::Pending),
            "processing" => Ok(Self::Processing),
            "complete" => Ok(Self::Complete),
            "failed" => Ok(Self::Failed),
            "canceled" => Ok(Self::Canceled),
            _ => Err(Error(format!("invalid sample status {}", value))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SampleStatusRecord {
    pub sha256: String,
    pub status: SampleStatus,
    pub timestamp: String,
    pub error_message: Option<String>,
    pub id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SampleTagRecord {
    pub sha256: String,
    pub tag: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectionTagRecord {
    pub sha256: String,
    pub collection: Collection,
    pub address: u64,
    pub tag: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SampleCommentRecord {
    pub sha256: String,
    pub comment: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectionCommentRecord {
    pub sha256: String,
    pub collection: Collection,
    pub address: u64,
    pub comment: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolRecord {
    pub symbol: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusRecord {
    pub corpus: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolSearchPage {
    pub items: Vec<String>,
    pub total_results: usize,
    pub has_next: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TagCatalogSearchPage {
    pub items: Vec<String>,
    pub total_results: usize,
    pub has_next: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct EntityCorpusRef {
    pub sha256: String,
    pub collection: Collection,
    pub architecture: String,
    pub address: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntityMetadataRecord {
    pub object_id: String,
    pub sha256: String,
    pub collection: Collection,
    pub architecture: String,
    pub username: String,
    pub address: u64,
    pub size: u64,
    pub cyclomatic_complexity: Option<u64>,
    pub average_instructions_per_block: Option<f64>,
    pub number_of_instructions: Option<u64>,
    pub number_of_blocks: Option<u64>,
    pub markov: Option<f64>,
    pub entropy: Option<f64>,
    pub contiguous: Option<bool>,
    pub chromosome_entropy: Option<f64>,
    pub timestamp: String,
    pub vector: Vec<f32>,
    pub attributes: Vec<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct SampleCorpusWrite {
    pub sha256: String,
    pub corpora: Vec<String>,
    pub timestamp: String,
}

#[derive(Debug, Clone)]
pub struct EntityCorpusWrite {
    pub sha256: String,
    pub collection: Collection,
    pub architecture: String,
    pub address: u64,
    pub corpora: Vec<String>,
    pub timestamp: String,
}

#[derive(Debug, Clone)]
pub struct EntityChildWrite {
    pub sha256: String,
    pub architecture: String,
    pub parent_collection: Collection,
    pub parent_address: u64,
    pub child_collection: Collection,
    pub child_addresses: Vec<u64>,
}

#[derive(Debug, Clone)]
pub struct EmbeddingCountDelta {
    pub collection: Collection,
    pub architecture: String,
    pub embedding: String,
    pub delta: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleRecord {
    pub name: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserRecord {
    pub username: String,
    pub role: String,
    pub enabled: bool,
    pub reserved: bool,
    pub timestamp: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenRecord {
    pub id: String,
    pub token: String,
    pub enabled: bool,
    pub timestamp: String,
    pub expires: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub page: usize,
    pub page_size: usize,
    pub has_next: bool,
}

pub struct LocalDB {
    sqlite: SQLite,
}

impl LocalDB {
    pub fn new(config: &Config) -> Result<Self, Error> {
        Self::with_path(config, None::<&Path>)
    }

    pub fn with_path(config: &Config, path: Option<impl AsRef<Path>>) -> Result<Self, Error> {
        let path = path
            .as_ref()
            .map(|value| value.as_ref())
            .unwrap_or_else(|| Path::new(&config.databases.local.path));
        let db = Self {
            sqlite: SQLite::new(path)?,
        };
        db.initialize()?;
        Ok(db)
    }

    pub fn sample_status_get(&self, sha256: &str) -> Result<Option<SampleStatusRecord>, Error> {
        let rows = self.sqlite.query(
            "SELECT sha256, status, timestamp, error_message, id FROM sample_status WHERE sha256 = ?1",
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

    pub fn sample_status_set(&self, status: &SampleStatusRecord) -> Result<(), Error> {
        self.sqlite.execute(
            "INSERT INTO sample_status (sha256, status, timestamp, error_message, id)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(sha256) DO UPDATE SET
               status = excluded.status,
               timestamp = excluded.timestamp,
               error_message = excluded.error_message,
               id = excluded.id",
            &[
                SQLiteValue::Text(status.sha256.clone()),
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

    pub fn corpus_add(&self, corpus: &str, timestamp: Option<&str>) -> Result<(), Error> {
        let corpus = corpus.trim();
        if corpus.is_empty() {
            return Err(Error("corpus must not be empty".to_string()));
        }
        let timestamp = timestamp
            .map(ToString::to_string)
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
        self.sqlite.execute(
            "INSERT INTO corpora_catalog (corpus, timestamp)
             VALUES (?1, ?2)
             ON CONFLICT(corpus) DO UPDATE SET
               timestamp = excluded.timestamp",
            &[
                SQLiteValue::Text(corpus.to_string()),
                SQLiteValue::Text(timestamp),
            ],
        )?;
        Ok(())
    }

    pub fn corpus_search(&self, query: &str, limit: usize) -> Result<Vec<String>, Error> {
        let limit = limit.max(1);
        let pattern = if query.trim().is_empty() {
            "%".to_string()
        } else {
            format!("%{}%", query.trim().to_ascii_lowercase())
        };
        let rows = self.sqlite.query(
            "SELECT corpus
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
                row.get("corpus")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| Error("corpus row is missing corpus".to_string()))
                    .map(ToString::to_string)
            })
            .collect()
    }

    pub fn entity_corpus_replace(
        &self,
        sha256: &str,
        collection: Collection,
        architecture: &str,
        address: u64,
        corpora: &[String],
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
            let corpus = corpus.trim();
            if corpus.is_empty() {
                continue;
            }
            self.sqlite.execute(
                "INSERT INTO entity_corpora (sha256, collection, architecture, address, corpus, timestamp)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(sha256, collection, architecture, address, corpus) DO UPDATE SET
                   timestamp = excluded.timestamp",
                &[
                    SQLiteValue::Text(sha256.to_string()),
                    SQLiteValue::Text(collection.as_str().to_string()),
                    SQLiteValue::Text(architecture.to_string()),
                    SQLiteValue::Integer(address as i64),
                    SQLiteValue::Text(corpus.to_string()),
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
        let rows = self.sqlite.query(
            "SELECT corpus
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
                row.get("corpus")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| Error("entity corpus row is missing corpus".to_string()))
                    .map(ToString::to_string)
            })
            .collect()
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
                    "instruction" => Collection::Instruction,
                    "block" => Collection::Block,
                    "function" => Collection::Function,
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
        self.sqlite.execute(
            "UPDATE entity_corpora SET corpus = ?2 WHERE corpus = ?1",
            &[
                SQLiteValue::Text(old_name.to_string()),
                SQLiteValue::Text(new_name.to_string()),
            ],
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
                "INSERT INTO entity_corpora (sha256, collection, architecture, address, corpus, timestamp)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(sha256, collection, architecture, address, corpus) DO UPDATE SET
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
                    let corpus = corpus.trim();
                    if corpus.is_empty() {
                        continue;
                    }
                    entity_insert.execute((
                        &write.sha256,
                        write.collection.as_str(),
                        &write.architecture,
                        write.address as i64,
                        corpus,
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
                    number_of_blocks, markov, entropy, contiguous, chromosome_entropy, timestamp,
                    vector_json, attributes_json
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)
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
                    timestamp = excluded.timestamp,
                    vector_json = excluded.vector_json,
                    attributes_json = excluded.attributes_json",
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
                    SQLiteValue::Text(record.timestamp.clone()),
                    SQLiteValue::Text(vector),
                    SQLiteValue::Text(attributes),
                ];
                metadata_upsert.execute(params_from_iter(params.iter()))?;
            }
        }

        transaction.commit()?;
        Ok(())
    }

    pub fn entity_metadata_upsert(&self, record: &EntityMetadataRecord) -> Result<(), Error> {
        let vector =
            serde_json::to_string(&record.vector).map_err(|error| Error(error.to_string()))?;
        let attributes =
            serde_json::to_string(&record.attributes).map_err(|error| Error(error.to_string()))?;
        self.sqlite.execute(
            "INSERT INTO entity_metadata (
                object_id, sha256, collection, architecture, username, address, size,
                cyclomatic_complexity, average_instructions_per_block, number_of_instructions,
                number_of_blocks, markov, entropy, contiguous, chromosome_entropy, timestamp,
                vector_json, attributes_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)
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
                SQLiteValue::Text(record.timestamp.clone()),
                SQLiteValue::Text(vector),
                SQLiteValue::Text(attributes),
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
                    number_of_blocks, markov, entropy, contiguous, chromosome_entropy, timestamp,
                    vector_json, attributes_json
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
                    number_of_blocks, markov, entropy, contiguous, chromosome_entropy, timestamp,
                    vector_json, attributes_json
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

    pub fn sample_tag_add(&self, tag: &SampleTagRecord) -> Result<(), Error> {
        self.sqlite.execute(
            "INSERT INTO sample_tags (sha256, tag, timestamp)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(sha256, tag) DO UPDATE SET
               timestamp = excluded.timestamp",
            &[
                SQLiteValue::Text(tag.sha256.clone()),
                SQLiteValue::Text(tag.tag.clone()),
                SQLiteValue::Text(tag.timestamp.clone()),
            ],
        )?;
        Ok(())
    }

    pub fn sample_tag_remove(&self, sha256: &str, tag: &str) -> Result<(), Error> {
        self.sqlite.execute(
            "DELETE FROM sample_tags WHERE sha256 = ?1 AND tag = ?2",
            &[
                SQLiteValue::Text(sha256.to_string()),
                SQLiteValue::Text(tag.to_string()),
            ],
        )?;
        Ok(())
    }

    pub fn sample_tag_list(&self, sha256: &str) -> Result<Vec<String>, Error> {
        let rows = self.sqlite.query(
            "SELECT tag
             FROM sample_tags
             WHERE sha256 = ?1
             ORDER BY tag ASC",
            &[SQLiteValue::Text(sha256.to_string())],
        )?;
        rows.into_iter()
            .map(|row| {
                row.get("tag")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| Error("sample tag row is missing tag".to_string()))
                    .map(ToString::to_string)
            })
            .collect()
    }

    pub fn sample_tag_replace(
        &self,
        sha256: &str,
        tags: &[String],
        timestamp: &str,
    ) -> Result<(), Error> {
        self.sqlite.execute(
            "DELETE FROM sample_tags WHERE sha256 = ?1",
            &[SQLiteValue::Text(sha256.to_string())],
        )?;
        for tag in tags {
            self.sample_tag_add(&SampleTagRecord {
                sha256: sha256.to_string(),
                tag: tag.clone(),
                timestamp: timestamp.to_string(),
            })?;
        }
        Ok(())
    }

    pub fn sample_tag_search(
        &self,
        query: &str,
        page: usize,
        page_size: usize,
    ) -> Result<Page<SampleTagRecord>, Error> {
        let page = page.max(1);
        let page_size = page_size.max(1);
        let offset = (page - 1) * page_size;
        let limit = page_size + 1;
        let pattern = if query.trim().is_empty() {
            "%".to_string()
        } else {
            format!("%{}%", query.trim().to_ascii_lowercase())
        };
        let rows = self.sqlite.query(
            "SELECT sha256, tag, timestamp
             FROM sample_tags
             WHERE LOWER(tag) LIKE ?1
             ORDER BY tag ASC, sha256 ASC
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
            .map(|row| -> Result<SampleTagRecord, Error> {
                Ok(SampleTagRecord {
                    sha256: row
                        .get("sha256")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| Error("sample tag row is missing sha256".to_string()))?
                        .to_string(),
                    tag: row
                        .get("tag")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| Error("sample tag row is missing tag".to_string()))?
                        .to_string(),
                    timestamp: row
                        .get("timestamp")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| Error("sample tag row is missing timestamp".to_string()))?
                        .to_string(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Page {
            items,
            page,
            page_size,
            has_next,
        })
    }

    pub fn tag_add(&self, tag: &str, timestamp: Option<&str>) -> Result<(), Error> {
        let tag = tag.trim();
        if tag.is_empty() {
            return Err(Error("tag must not be empty".to_string()));
        }
        let timestamp = timestamp
            .map(ToString::to_string)
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
        self.sqlite.execute(
            "INSERT INTO tags (tag, timestamp)
             VALUES (?1, ?2)
             ON CONFLICT(tag) DO UPDATE SET
               timestamp = excluded.timestamp",
            &[
                SQLiteValue::Text(tag.to_string()),
                SQLiteValue::Text(timestamp),
            ],
        )?;
        Ok(())
    }

    pub fn tag_search(&self, query: &str, limit: usize) -> Result<TagCatalogSearchPage, Error> {
        let limit = limit.max(1);
        let pattern = if query.trim().is_empty() {
            "%".to_string()
        } else {
            format!("%{}%", query.trim().to_ascii_lowercase())
        };
        let total_rows = self.sqlite.query(
            "SELECT COUNT(*) AS count
             FROM tags
             WHERE LOWER(tag) LIKE ?1",
            &[SQLiteValue::Text(pattern.clone())],
        )?;
        let total_results = total_rows
            .into_iter()
            .next()
            .and_then(|row| row.get("count").and_then(|value| value.as_i64()))
            .unwrap_or(0)
            .max(0) as usize;
        let rows = self.sqlite.query(
            "SELECT tag
             FROM tags
             WHERE LOWER(tag) LIKE ?1
             ORDER BY tag ASC
             LIMIT ?2",
            &[
                SQLiteValue::Text(pattern),
                SQLiteValue::Integer(limit as i64),
            ],
        )?;
        let items = rows
            .into_iter()
            .map(|row| {
                row.get("tag")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| Error("tag row is missing tag".to_string()))
                    .map(ToString::to_string)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(TagCatalogSearchPage {
            has_next: total_results > items.len(),
            total_results,
            items,
        })
    }

    pub fn collection_tag_add(&self, tag: &CollectionTagRecord) -> Result<(), Error> {
        self.tag_add(&tag.tag, Some(&tag.timestamp))?;
        self.sqlite.execute(
            "INSERT INTO collection_tags (sha256, collection, address, tag, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(sha256, collection, address, tag) DO UPDATE SET
               timestamp = excluded.timestamp",
            &[
                SQLiteValue::Text(tag.sha256.clone()),
                SQLiteValue::Text(tag.collection.as_str().to_string()),
                SQLiteValue::Integer(tag.address as i64),
                SQLiteValue::Text(tag.tag.clone()),
                SQLiteValue::Text(tag.timestamp.clone()),
            ],
        )?;
        Ok(())
    }

    pub fn collection_tag_add_many(&self, tags: &[CollectionTagRecord]) -> Result<(), Error> {
        if tags.is_empty() {
            return Ok(());
        }

        let mut connection = self.sqlite.connection()?;
        let transaction = connection.transaction()?;

        {
            let mut tag_upsert = transaction.prepare(
                "INSERT INTO tags (tag, timestamp)
                 VALUES (?1, ?2)
                 ON CONFLICT(tag) DO UPDATE SET
                   timestamp = excluded.timestamp",
            )?;
            let mut collection_tag_upsert = transaction.prepare(
                "INSERT INTO collection_tags (sha256, collection, address, tag, timestamp)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(sha256, collection, address, tag) DO UPDATE SET
                   timestamp = excluded.timestamp",
            )?;

            for record in tags {
                let tag = record.tag.trim();
                if tag.is_empty() {
                    return Err(Error("tag must not be empty".to_string()));
                }
                tag_upsert.execute((tag, &record.timestamp))?;
                collection_tag_upsert.execute((
                    &record.sha256,
                    record.collection.as_str(),
                    record.address as i64,
                    tag,
                    &record.timestamp,
                ))?;
            }
        }

        transaction.commit()?;
        Ok(())
    }

    pub fn collection_tag_remove(
        &self,
        sha256: &str,
        collection: Collection,
        address: u64,
        tag: &str,
    ) -> Result<(), Error> {
        self.sqlite.execute(
            "DELETE FROM collection_tags
             WHERE sha256 = ?1 AND collection = ?2 AND address = ?3 AND tag = ?4",
            &[
                SQLiteValue::Text(sha256.to_string()),
                SQLiteValue::Text(collection.as_str().to_string()),
                SQLiteValue::Integer(address as i64),
                SQLiteValue::Text(tag.to_string()),
            ],
        )?;
        Ok(())
    }

    pub fn collection_tag_replace(
        &self,
        sha256: &str,
        collection: Collection,
        address: u64,
        tags: &[String],
        timestamp: &str,
    ) -> Result<(), Error> {
        self.sqlite.execute(
            "DELETE FROM collection_tags WHERE sha256 = ?1 AND collection = ?2 AND address = ?3",
            &[
                SQLiteValue::Text(sha256.to_string()),
                SQLiteValue::Text(collection.as_str().to_string()),
                SQLiteValue::Integer(address as i64),
            ],
        )?;
        for tag in tags {
            self.collection_tag_add(&CollectionTagRecord {
                sha256: sha256.to_string(),
                collection,
                address,
                tag: tag.clone(),
                timestamp: timestamp.to_string(),
            })?;
        }
        Ok(())
    }

    pub fn collection_tag_list(
        &self,
        sha256: &str,
        collection: Collection,
        address: u64,
    ) -> Result<Vec<String>, Error> {
        let rows = self.sqlite.query(
            "SELECT tag
             FROM collection_tags
             WHERE sha256 = ?1 AND collection = ?2 AND address = ?3
             ORDER BY tag ASC",
            &[
                SQLiteValue::Text(sha256.to_string()),
                SQLiteValue::Text(collection.as_str().to_string()),
                SQLiteValue::Integer(address as i64),
            ],
        )?;
        rows.into_iter()
            .map(|row| {
                row.get("tag")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| Error("collection tag row is missing tag".to_string()))
                    .map(ToString::to_string)
            })
            .collect()
    }

    pub fn collection_tag_count(
        &self,
        sha256: &str,
        collection: Collection,
        address: u64,
    ) -> Result<usize, Error> {
        let rows = self.sqlite.query(
            "SELECT COUNT(*) AS count
             FROM collection_tags
             WHERE sha256 = ?1 AND collection = ?2 AND address = ?3",
            &[
                SQLiteValue::Text(sha256.to_string()),
                SQLiteValue::Text(collection.as_str().to_string()),
                SQLiteValue::Integer(address as i64),
            ],
        )?;
        let Some(row) = rows.first() else {
            return Ok(0);
        };
        row.get("count")
            .and_then(|value| value.as_i64())
            .map(|value| value.max(0) as usize)
            .ok_or_else(|| Error("collection tag count row is missing count".to_string()))
    }

    pub fn collection_tag_counts(
        &self,
        keys: &[(String, Collection, u64)],
    ) -> Result<BTreeMap<(String, Collection, u64), usize>, Error> {
        let mut counts = BTreeMap::new();
        if keys.is_empty() {
            return Ok(counts);
        }
        let mut sql = String::from(
            "SELECT sha256, collection, address, COUNT(*) AS count
             FROM collection_tags
             WHERE ",
        );
        let mut params = Vec::with_capacity(keys.len() * 3);
        for (index, (sha256, collection, address)) in keys.iter().enumerate() {
            if index > 0 {
                sql.push_str(" OR ");
            }
            sql.push_str("(sha256 = ? AND collection = ? AND address = ?)");
            params.push(SQLiteValue::Text(sha256.clone()));
            params.push(SQLiteValue::Text(collection.as_str().to_string()));
            params.push(SQLiteValue::Integer(*address as i64));
        }
        sql.push_str(" GROUP BY sha256, collection, address");
        let rows = self.sqlite.query(&sql, &params)?;
        for row in rows {
            let sha256 = row
                .get("sha256")
                .and_then(|value| value.as_str())
                .ok_or_else(|| Error("collection tag count row is missing sha256".to_string()))?
                .to_string();
            let collection = row
                .get("collection")
                .and_then(|value| value.as_str())
                .ok_or_else(|| Error("collection tag count row is missing collection".to_string()))
                .and_then(|value| match value {
                    "function" => Ok(Collection::Function),
                    "block" => Ok(Collection::Block),
                    "instruction" => Ok(Collection::Instruction),
                    _ => Err(Error(format!(
                        "collection tag count row has invalid collection {}",
                        value
                    ))),
                })?;
            let address = row
                .get("address")
                .and_then(|value| value.as_i64())
                .ok_or_else(|| Error("collection tag count row is missing address".to_string()))?
                .max(0) as u64;
            let count = row
                .get("count")
                .and_then(|value| value.as_i64())
                .ok_or_else(|| Error("collection tag count row is missing count".to_string()))?
                .max(0) as usize;
            counts.insert((sha256, collection, address), count);
        }
        Ok(counts)
    }

    pub fn collection_tag_search(
        &self,
        query: &str,
        collection: Option<Collection>,
        page: usize,
        page_size: usize,
    ) -> Result<Page<CollectionTagRecord>, Error> {
        let page = page.max(1);
        let page_size = page_size.max(1);
        let offset = (page - 1) * page_size;
        let limit = page_size + 1;
        let pattern = if query.trim().is_empty() {
            "%".to_string()
        } else {
            format!("%{}%", query.trim().to_ascii_lowercase())
        };
        let (sql, params) = if let Some(collection) = collection {
            (
                "SELECT sha256, collection, address, tag, timestamp
                 FROM collection_tags
                 WHERE LOWER(tag) LIKE ?1 AND collection = ?2
                 ORDER BY tag ASC, sha256 ASC, address ASC
                 LIMIT ?3 OFFSET ?4",
                vec![
                    SQLiteValue::Text(pattern),
                    SQLiteValue::Text(collection.as_str().to_string()),
                    SQLiteValue::Integer(limit as i64),
                    SQLiteValue::Integer(offset as i64),
                ],
            )
        } else {
            (
                "SELECT sha256, collection, address, tag, timestamp
                 FROM collection_tags
                 WHERE LOWER(tag) LIKE ?1
                 ORDER BY tag ASC, collection ASC, sha256 ASC, address ASC
                 LIMIT ?2 OFFSET ?3",
                vec![
                    SQLiteValue::Text(pattern),
                    SQLiteValue::Integer(limit as i64),
                    SQLiteValue::Integer(offset as i64),
                ],
            )
        };
        let rows = self.sqlite.query(sql, &params)?;
        let has_next = rows.len() > page_size;
        let items = rows
            .into_iter()
            .take(page_size)
            .map(|row| -> Result<CollectionTagRecord, Error> {
                let collection = row
                    .get("collection")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| Error("collection tag row is missing collection".to_string()))
                    .and_then(parse_collection)?;
                Ok(CollectionTagRecord {
                    sha256: row
                        .get("sha256")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| Error("collection tag row is missing sha256".to_string()))?
                        .to_string(),
                    collection,
                    address: row
                        .get("address")
                        .and_then(|value| value.as_u64())
                        .ok_or_else(|| {
                            Error("collection tag row is missing address".to_string())
                        })?,
                    tag: row
                        .get("tag")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| Error("collection tag row is missing tag".to_string()))?
                        .to_string(),
                    timestamp: row
                        .get("timestamp")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| {
                            Error("collection tag row is missing timestamp".to_string())
                        })?
                        .to_string(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Page {
            items,
            page,
            page_size,
            has_next,
        })
    }

    pub fn sample_comment_add_record(&self, comment: &SampleCommentRecord) -> Result<(), Error> {
        self.sqlite.execute(
            "INSERT INTO sample_comments (sha256, comment, timestamp)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(sha256, comment) DO UPDATE SET
               timestamp = excluded.timestamp",
            &[
                SQLiteValue::Text(comment.sha256.clone()),
                SQLiteValue::Text(comment.comment.clone()),
                SQLiteValue::Text(comment.timestamp.clone()),
            ],
        )?;
        Ok(())
    }

    pub fn sample_comment_add(
        &self,
        sha256: &str,
        comment: &str,
        timestamp: Option<&str>,
    ) -> Result<(), Error> {
        let comment = comment.trim();
        if comment.is_empty() {
            return Err(Error("comment must not be empty".to_string()));
        }
        let timestamp = timestamp
            .map(ToString::to_string)
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
        self.sample_comment_add_record(&SampleCommentRecord {
            sha256: sha256.to_string(),
            comment: comment.to_string(),
            timestamp,
        })
    }

    pub fn sample_comment_remove_record(&self, sha256: &str, comment: &str) -> Result<(), Error> {
        self.sqlite.execute(
            "DELETE FROM sample_comments WHERE sha256 = ?1 AND comment = ?2",
            &[
                SQLiteValue::Text(sha256.to_string()),
                SQLiteValue::Text(comment.to_string()),
            ],
        )?;
        Ok(())
    }

    pub fn sample_comment_remove(&self, sha256: &str, comment: &str) -> Result<(), Error> {
        let comment = comment.trim();
        if comment.is_empty() {
            return Err(Error("comment must not be empty".to_string()));
        }
        self.sample_comment_remove_record(sha256, comment)
    }

    pub fn sample_comment_replace(
        &self,
        sha256: &str,
        comments: &[String],
        timestamp: Option<&str>,
    ) -> Result<(), Error> {
        self.sqlite.execute(
            "DELETE FROM sample_comments WHERE sha256 = ?1",
            &[SQLiteValue::Text(sha256.to_string())],
        )?;
        let timestamp = timestamp
            .map(ToString::to_string)
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
        for comment in comments
            .iter()
            .map(|comment| comment.trim())
            .filter(|comment| !comment.is_empty())
        {
            self.sample_comment_add_record(&SampleCommentRecord {
                sha256: sha256.to_string(),
                comment: comment.to_string(),
                timestamp: timestamp.clone(),
            })?;
        }
        Ok(())
    }

    pub fn sample_comment_search(
        &self,
        query: &str,
        page: usize,
        page_size: usize,
    ) -> Result<Page<SampleCommentRecord>, Error> {
        let page = page.max(1);
        let page_size = page_size.max(1);
        let offset = (page - 1) * page_size;
        let limit = page_size + 1;
        let pattern = if query.trim().is_empty() {
            "%".to_string()
        } else {
            format!("%{}%", query.trim().to_ascii_lowercase())
        };
        let rows = self.sqlite.query(
            "SELECT sha256, comment, timestamp
             FROM sample_comments
             WHERE LOWER(comment) LIKE ?1
             ORDER BY timestamp DESC, sha256 ASC, comment ASC
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
            .map(|row| -> Result<SampleCommentRecord, Error> {
                Ok(SampleCommentRecord {
                    sha256: row
                        .get("sha256")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| Error("sample comment row is missing sha256".to_string()))?
                        .to_string(),
                    comment: row
                        .get("comment")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| Error("sample comment row is missing comment".to_string()))?
                        .to_string(),
                    timestamp: row
                        .get("timestamp")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| {
                            Error("sample comment row is missing timestamp".to_string())
                        })?
                        .to_string(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Page {
            items,
            page,
            page_size,
            has_next,
        })
    }

    pub fn collection_comment_add(
        &self,
        sha256: &str,
        collection: Collection,
        address: u64,
        comment: &str,
        timestamp: Option<&str>,
    ) -> Result<(), Error> {
        let comment = comment.trim();
        if comment.is_empty() {
            return Err(Error("comment must not be empty".to_string()));
        }
        let timestamp = timestamp
            .map(ToString::to_string)
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
        self.sqlite.execute(
            "INSERT INTO collection_comments (sha256, collection, address, comment, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(sha256, collection, address, comment) DO UPDATE SET
               timestamp = excluded.timestamp",
            &[
                SQLiteValue::Text(sha256.to_string()),
                SQLiteValue::Text(collection.as_str().to_string()),
                SQLiteValue::Integer(address as i64),
                SQLiteValue::Text(comment.to_string()),
                SQLiteValue::Text(timestamp),
            ],
        )?;
        Ok(())
    }

    pub fn collection_comment_remove(
        &self,
        sha256: &str,
        collection: Collection,
        address: u64,
        comment: &str,
    ) -> Result<(), Error> {
        let comment = comment.trim();
        if comment.is_empty() {
            return Err(Error("comment must not be empty".to_string()));
        }
        self.sqlite.execute(
            "DELETE FROM collection_comments
             WHERE sha256 = ?1 AND collection = ?2 AND address = ?3 AND comment = ?4",
            &[
                SQLiteValue::Text(sha256.to_string()),
                SQLiteValue::Text(collection.as_str().to_string()),
                SQLiteValue::Integer(address as i64),
                SQLiteValue::Text(comment.to_string()),
            ],
        )?;
        Ok(())
    }

    pub fn collection_comment_replace(
        &self,
        sha256: &str,
        collection: Collection,
        address: u64,
        comments: &[String],
        timestamp: Option<&str>,
    ) -> Result<(), Error> {
        self.sqlite.execute(
            "DELETE FROM collection_comments WHERE sha256 = ?1 AND collection = ?2 AND address = ?3",
            &[
                SQLiteValue::Text(sha256.to_string()),
                SQLiteValue::Text(collection.as_str().to_string()),
                SQLiteValue::Integer(address as i64),
            ],
        )?;
        let timestamp = timestamp
            .map(ToString::to_string)
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
        for comment in comments
            .iter()
            .map(|comment| comment.trim())
            .filter(|comment| !comment.is_empty())
        {
            self.collection_comment_add(sha256, collection, address, comment, Some(&timestamp))?;
        }
        Ok(())
    }

    pub fn collection_comment_search(
        &self,
        query: &str,
        collection: Option<Collection>,
        page: usize,
        page_size: usize,
    ) -> Result<Page<CollectionCommentRecord>, Error> {
        let page = page.max(1);
        let page_size = page_size.max(1);
        let offset = (page - 1) * page_size;
        let limit = page_size + 1;
        let pattern = if query.trim().is_empty() {
            "%".to_string()
        } else {
            format!("%{}%", query.trim().to_ascii_lowercase())
        };
        let (sql, params) = if let Some(collection) = collection {
            (
                "SELECT sha256, collection, address, comment, timestamp
                 FROM collection_comments
                 WHERE LOWER(comment) LIKE ?1 AND collection = ?2
                 ORDER BY timestamp DESC, sha256 ASC, address ASC, comment ASC
                 LIMIT ?3 OFFSET ?4",
                vec![
                    SQLiteValue::Text(pattern),
                    SQLiteValue::Text(collection.as_str().to_string()),
                    SQLiteValue::Integer(limit as i64),
                    SQLiteValue::Integer(offset as i64),
                ],
            )
        } else {
            (
                "SELECT sha256, collection, address, comment, timestamp
                 FROM collection_comments
                 WHERE LOWER(comment) LIKE ?1
                 ORDER BY timestamp DESC, collection ASC, sha256 ASC, address ASC, comment ASC
                 LIMIT ?2 OFFSET ?3",
                vec![
                    SQLiteValue::Text(pattern),
                    SQLiteValue::Integer(limit as i64),
                    SQLiteValue::Integer(offset as i64),
                ],
            )
        };
        let rows = self.sqlite.query(sql, &params)?;
        let has_next = rows.len() > page_size;
        let items = rows
            .into_iter()
            .take(page_size)
            .map(|row| -> Result<CollectionCommentRecord, Error> {
                let collection = row
                    .get("collection")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| {
                        Error("collection comment row is missing collection".to_string())
                    })
                    .and_then(parse_collection)?;
                Ok(CollectionCommentRecord {
                    sha256: row
                        .get("sha256")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| {
                            Error("collection comment row is missing sha256".to_string())
                        })?
                        .to_string(),
                    collection,
                    address: row
                        .get("address")
                        .and_then(|value| value.as_u64())
                        .ok_or_else(|| {
                            Error("collection comment row is missing address".to_string())
                        })?,
                    comment: row
                        .get("comment")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| {
                            Error("collection comment row is missing comment".to_string())
                        })?
                        .to_string(),
                    timestamp: row
                        .get("timestamp")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| {
                            Error("collection comment row is missing timestamp".to_string())
                        })?
                        .to_string(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Page {
            items,
            page,
            page_size,
            has_next,
        })
    }

    pub fn symbol_add(&self, symbol: &str, timestamp: Option<&str>) -> Result<(), Error> {
        let symbol = symbol.trim();
        if symbol.is_empty() {
            return Err(Error("symbol must not be empty".to_string()));
        }
        let timestamp = timestamp
            .map(ToString::to_string)
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
        self.sqlite.execute(
            "INSERT INTO symbols (symbol, timestamp)
             VALUES (?1, ?2)
             ON CONFLICT(symbol) DO UPDATE SET
               timestamp = excluded.timestamp",
            &[
                SQLiteValue::Text(symbol.to_string()),
                SQLiteValue::Text(timestamp),
            ],
        )?;
        Ok(())
    }

    pub fn symbol_search(&self, query: &str, limit: usize) -> Result<SymbolSearchPage, Error> {
        let limit = limit.max(1);
        let pattern = if query.trim().is_empty() {
            "%".to_string()
        } else {
            format!("%{}%", query.trim().to_ascii_lowercase())
        };
        let total_rows = self.sqlite.query(
            "SELECT COUNT(*) AS count
             FROM symbols
             WHERE LOWER(symbol) LIKE ?1",
            &[SQLiteValue::Text(pattern.clone())],
        )?;
        let total_results = total_rows
            .into_iter()
            .next()
            .and_then(|row| row.get("count").and_then(|value| value.as_i64()))
            .unwrap_or(0)
            .max(0) as usize;
        let rows = self.sqlite.query(
            "SELECT symbol
             FROM symbols
             WHERE LOWER(symbol) LIKE ?1
             ORDER BY symbol ASC
             LIMIT ?2",
            &[
                SQLiteValue::Text(pattern),
                SQLiteValue::Integer(limit as i64),
            ],
        )?;
        let items = rows
            .into_iter()
            .map(|row| {
                row.get("symbol")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| Error("symbol row is missing symbol".to_string()))
                    .map(ToString::to_string)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(SymbolSearchPage {
            has_next: total_results > items.len(),
            total_results,
            items,
        })
    }

    pub fn role_create(&self, name: &str, timestamp: Option<&str>) -> Result<RoleRecord, Error> {
        let name = normalize_role_name(name)?;
        let record = RoleRecord {
            name: name.to_string(),
            timestamp: timestamp
                .map(ToString::to_string)
                .unwrap_or_else(|| chrono::Utc::now().to_rfc3339()),
        };
        self.sqlite.execute(
            "INSERT INTO roles (name, timestamp)
             VALUES (?1, ?2)",
            &[
                SQLiteValue::Text(record.name.clone()),
                SQLiteValue::Text(record.timestamp.clone()),
            ],
        )?;
        Ok(record)
    }

    pub fn role_get(&self, name: &str) -> Result<Option<RoleRecord>, Error> {
        let name = normalize_role_name(name)?;
        let rows = self.sqlite.query(
            "SELECT name, timestamp FROM roles WHERE name = ?1 LIMIT 1",
            &[SQLiteValue::Text(name.to_string())],
        )?;
        Ok(rows.into_iter().next().map(|row| RoleRecord {
            name: row
                .get("name")
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_string(),
            timestamp: row
                .get("timestamp")
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_string(),
        }))
    }

    pub fn role_search(
        &self,
        query: &str,
        page: usize,
        limit: usize,
    ) -> Result<Page<RoleRecord>, Error> {
        let page = page.max(1);
        let limit = limit.max(1);
        let offset = (page - 1) * limit;
        let like = format!("%{}%", query.trim().to_ascii_lowercase());
        let rows = self.sqlite.query(
            "SELECT name, timestamp
             FROM roles
             WHERE lower(name) LIKE ?1
             ORDER BY name ASC
             LIMIT ?2 OFFSET ?3",
            &[
                SQLiteValue::Text(like),
                SQLiteValue::Integer((limit + 1) as i64),
                SQLiteValue::Integer(offset as i64),
            ],
        )?;
        let has_next = rows.len() > limit;
        let items = rows
            .into_iter()
            .take(limit)
            .map(|row| RoleRecord {
                name: row
                    .get("name")
                    .and_then(|value| value.as_str())
                    .unwrap_or_default()
                    .to_string(),
                timestamp: row
                    .get("timestamp")
                    .and_then(|value| value.as_str())
                    .unwrap_or_default()
                    .to_string(),
            })
            .collect();
        Ok(Page {
            items,
            page,
            page_size: limit,
            has_next,
        })
    }

    pub fn role_delete(&self, name: &str) -> Result<bool, Error> {
        let name = normalize_role_name(name)?;
        if is_reserved_role(name) {
            return Err(Error(format!("role {} is reserved", name)));
        }
        if self.role_get(name)?.is_none() {
            return Ok(false);
        }
        let in_use = self.sqlite.query(
            "SELECT username FROM users WHERE role = ?1 LIMIT 1",
            &[SQLiteValue::Text(name.to_string())],
        )?;
        if !in_use.is_empty() {
            return Err(Error(format!("role {} is still in use", name)));
        }
        self.sqlite.execute(
            "DELETE FROM roles WHERE name = ?1",
            &[SQLiteValue::Text(name.to_string())],
        )?;
        let rows = self.sqlite.query(
            "SELECT name FROM roles WHERE name = ?1",
            &[SQLiteValue::Text(name.to_string())],
        )?;
        Ok(rows.is_empty())
    }

    pub fn user_create(
        &self,
        username: &str,
        role: &str,
        timestamp: Option<&str>,
    ) -> Result<(UserRecord, String), Error> {
        let plaintext = generate_api_key();
        let record = self.user_create_with_key(username, role, &plaintext, false, timestamp)?;
        Ok((record, plaintext))
    }

    pub fn user_disable(&self, username: &str) -> Result<bool, Error> {
        let username = normalize_username(username)?;
        let current = self
            .user_get(username)?
            .ok_or_else(|| Error(format!("user {} does not exist", username)))?;
        if current.reserved {
            return Err(Error(format!("user {} is reserved", username)));
        }
        self.sqlite.execute(
            "UPDATE users SET enabled = 0 WHERE username = ?1",
            &[SQLiteValue::Text(username.to_string())],
        )?;
        Ok(true)
    }

    pub fn user_enable(&self, username: &str) -> Result<bool, Error> {
        let username = normalize_username(username)?;
        self.sqlite.execute(
            "UPDATE users SET enabled = 1 WHERE username = ?1",
            &[SQLiteValue::Text(username.to_string())],
        )?;
        Ok(self.user_get(username)?.is_some())
    }

    pub fn user_reset(&self, username: &str, timestamp: Option<&str>) -> Result<String, Error> {
        let username = normalize_username(username)?;
        let current = self
            .user_get(username)?
            .ok_or_else(|| Error(format!("user {} does not exist", username)))?;
        if current.reserved {
            return Err(Error(format!("user {} is reserved", username)));
        }
        let plaintext = generate_api_key();
        let when = timestamp
            .map(ToString::to_string)
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
        self.sqlite.execute(
            "UPDATE users SET api_key = ?1, timestamp = ?2 WHERE username = ?3",
            &[
                SQLiteValue::Text(hash_api_key(&plaintext)),
                SQLiteValue::Text(when),
                SQLiteValue::Text(username.to_string()),
            ],
        )?;
        Ok(plaintext)
    }

    pub fn user_get(&self, username: &str) -> Result<Option<UserRecord>, Error> {
        let username = normalize_username(username)?;
        let rows = self.sqlite.query(
            "SELECT username, role, enabled, reserved, timestamp
             FROM users
             WHERE username = ?1
             LIMIT 1",
            &[SQLiteValue::Text(username.to_string())],
        )?;
        Ok(rows
            .into_iter()
            .next()
            .map(user_record_from_row)
            .transpose()?)
    }

    pub fn user_search(
        &self,
        query: &str,
        page: usize,
        limit: usize,
    ) -> Result<Page<UserRecord>, Error> {
        let page = page.max(1);
        let limit = limit.max(1);
        let offset = (page - 1) * limit;
        let like = format!("%{}%", query.trim().to_ascii_lowercase());
        let rows = self.sqlite.query(
            "SELECT username, role, enabled, reserved, timestamp
             FROM users
             WHERE lower(username) LIKE ?1 OR lower(role) LIKE ?1
             ORDER BY reserved DESC, username ASC
             LIMIT ?2 OFFSET ?3",
            &[
                SQLiteValue::Text(like),
                SQLiteValue::Integer((limit + 1) as i64),
                SQLiteValue::Integer(offset as i64),
            ],
        )?;
        let has_next = rows.len() > limit;
        let items = rows
            .into_iter()
            .take(limit)
            .map(user_record_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Page {
            items,
            page,
            page_size: limit,
            has_next,
        })
    }

    pub fn auth_check(&self, api_key: &str) -> Result<bool, Error> {
        Ok(self.auth_user(api_key)?.is_some())
    }

    pub fn auth_user(&self, api_key: &str) -> Result<Option<UserRecord>, Error> {
        let api_key = api_key.trim();
        if api_key.is_empty() {
            return Ok(None);
        }
        let rows = self.sqlite.query(
            "SELECT username, role, enabled, reserved, timestamp
             FROM users
             WHERE api_key = ?1 AND enabled = 1
             LIMIT 1",
            &[SQLiteValue::Text(hash_api_key(api_key))],
        )?;
        Ok(rows
            .into_iter()
            .next()
            .map(user_record_from_row)
            .transpose()?)
    }

    pub fn token_create(&self, ttl_seconds: u64) -> Result<(TokenRecord, String), Error> {
        let plaintext = generate_secret();
        let now = chrono::Utc::now();
        let expires = now
            .checked_add_signed(chrono::TimeDelta::seconds(ttl_seconds as i64))
            .ok_or_else(|| Error("failed to compute token expiry".to_string()))?;
        let record = TokenRecord {
            id: generate_token_id(),
            token: hash_secret(&plaintext),
            enabled: true,
            timestamp: now.to_rfc3339(),
            expires: expires.to_rfc3339(),
        };
        self.sqlite.execute(
            "INSERT INTO tokens (id, token, enabled, timestamp, expires)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &[
                SQLiteValue::Text(record.id.clone()),
                SQLiteValue::Text(record.token.clone()),
                SQLiteValue::Integer(if record.enabled { 1 } else { 0 }),
                SQLiteValue::Text(record.timestamp.clone()),
                SQLiteValue::Text(record.expires.clone()),
            ],
        )?;
        Ok((record, plaintext))
    }

    pub fn token_check(&self, token: &str) -> Result<bool, Error> {
        let token = token.trim();
        if token.is_empty() {
            return Ok(false);
        }
        let rows = self.sqlite.query(
            "SELECT enabled, expires
             FROM tokens
             WHERE token = ?1
             LIMIT 1",
            &[SQLiteValue::Text(hash_secret(token))],
        )?;
        let Some(row) = rows.into_iter().next() else {
            return Ok(false);
        };
        let enabled = row
            .get("enabled")
            .and_then(|value| value.as_i64())
            .map(|value| value != 0)
            .ok_or_else(|| Error("token row is missing enabled".to_string()))?;
        if !enabled {
            return Ok(false);
        }
        let expires = row
            .get("expires")
            .and_then(|value| value.as_str())
            .ok_or_else(|| Error("token row is missing expires".to_string()))?;
        let expires = chrono::DateTime::parse_from_rfc3339(expires)
            .map_err(|error| Error(format!("invalid token expiry {}: {}", expires, error)))?
            .with_timezone(&chrono::Utc);
        Ok(chrono::Utc::now() < expires)
    }

    pub fn token_disable(&self, id: &str) -> Result<bool, Error> {
        let id = id.trim();
        if id.is_empty() {
            return Err(Error("id must not be empty".to_string()));
        }
        self.sqlite.execute(
            "UPDATE tokens SET enabled = 0 WHERE id = ?1",
            &[SQLiteValue::Text(id.to_string())],
        )?;
        let rows = self.sqlite.query(
            "SELECT enabled FROM tokens WHERE id = ?1",
            &[SQLiteValue::Text(id.to_string())],
        )?;
        Ok(!rows.is_empty())
    }

    pub fn token_disable_value(&self, token: &str) -> Result<bool, Error> {
        let token = token.trim();
        if token.is_empty() {
            return Err(Error("token must not be empty".to_string()));
        }
        self.sqlite.execute(
            "UPDATE tokens SET enabled = 0 WHERE token = ?1",
            &[SQLiteValue::Text(hash_secret(token))],
        )?;
        let rows = self.sqlite.query(
            "SELECT enabled FROM tokens WHERE token = ?1",
            &[SQLiteValue::Text(hash_secret(token))],
        )?;
        Ok(!rows.is_empty())
    }

    pub fn token_clear(&self) -> Result<usize, Error> {
        let now = chrono::Utc::now().to_rfc3339();
        let before = self.sqlite.query(
            "SELECT id FROM tokens WHERE expires <= ?1",
            &[SQLiteValue::Text(now.clone())],
        )?;
        self.sqlite.execute(
            "DELETE FROM tokens WHERE expires <= ?1",
            &[SQLiteValue::Text(now)],
        )?;
        Ok(before.len())
    }

    fn initialize(&self) -> Result<(), Error> {
        self.sqlite.execute_batch(
            "CREATE TABLE IF NOT EXISTS sample_status (
                sha256 TEXT PRIMARY KEY NOT NULL,
                status TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                error_message TEXT NULL,
                id TEXT NULL
            );
            CREATE TABLE IF NOT EXISTS sample_tags (
                sha256 TEXT NOT NULL,
                tag TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                PRIMARY KEY (sha256, tag)
            );
            CREATE TABLE IF NOT EXISTS tags (
                tag TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                PRIMARY KEY (tag)
            );
            CREATE TABLE IF NOT EXISTS collection_tags (
                sha256 TEXT NOT NULL,
                collection TEXT NOT NULL,
                address INTEGER NOT NULL,
                tag TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                PRIMARY KEY (sha256, collection, address, tag)
            );
            CREATE TABLE IF NOT EXISTS entity_corpora (
                sha256 TEXT NOT NULL,
                collection TEXT NOT NULL,
                architecture TEXT NOT NULL,
                address INTEGER NOT NULL,
                corpus TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                PRIMARY KEY (sha256, collection, architecture, address, corpus)
            );
            CREATE TABLE IF NOT EXISTS corpora_catalog (
                corpus TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                PRIMARY KEY (corpus)
            );
            CREATE TABLE IF NOT EXISTS entity_children (
                sha256 TEXT NOT NULL,
                architecture TEXT NOT NULL,
                parent_collection TEXT NOT NULL,
                parent_address INTEGER NOT NULL,
                child_collection TEXT NOT NULL,
                child_address INTEGER NOT NULL,
                PRIMARY KEY (
                    sha256,
                    architecture,
                    parent_collection,
                    parent_address,
                    child_collection,
                    child_address
                )
            );
            CREATE TABLE IF NOT EXISTS embedding_counts (
                collection TEXT NOT NULL,
                architecture TEXT NOT NULL,
                embedding TEXT NOT NULL,
                count INTEGER NOT NULL,
                PRIMARY KEY (collection, architecture, embedding)
            );
            CREATE TABLE IF NOT EXISTS entity_metadata (
                object_id TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                collection TEXT NOT NULL,
                architecture TEXT NOT NULL,
                username TEXT NOT NULL,
                address INTEGER NOT NULL,
                size INTEGER NOT NULL,
                cyclomatic_complexity INTEGER NULL,
                average_instructions_per_block REAL NULL,
                number_of_instructions INTEGER NULL,
                number_of_blocks INTEGER NULL,
                markov REAL NULL,
                entropy REAL NULL,
                contiguous INTEGER NULL,
                chromosome_entropy REAL NULL,
                timestamp TEXT NOT NULL,
                vector_json TEXT NOT NULL,
                attributes_json TEXT NOT NULL,
                PRIMARY KEY (collection, architecture, object_id)
            );
            CREATE TABLE IF NOT EXISTS sample_comments (
                sha256 TEXT NOT NULL,
                comment TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                PRIMARY KEY (sha256, comment)
            );
            CREATE TABLE IF NOT EXISTS collection_comments (
                sha256 TEXT NOT NULL,
                collection TEXT NOT NULL,
                address INTEGER NOT NULL,
                comment TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                PRIMARY KEY (sha256, collection, address, comment)
            );
            CREATE TABLE IF NOT EXISTS symbols (
                symbol TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                PRIMARY KEY (symbol)
            );
            CREATE TABLE IF NOT EXISTS roles (
                name TEXT PRIMARY KEY NOT NULL,
                timestamp TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY NOT NULL,
                role TEXT NOT NULL,
                api_key TEXT NOT NULL,
                enabled INTEGER NOT NULL,
                reserved INTEGER NOT NULL,
                timestamp TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS tokens (
                id TEXT PRIMARY KEY NOT NULL,
                token TEXT NOT NULL,
                enabled INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                expires TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_corpora_catalog_corpus ON corpora_catalog (corpus);
            CREATE INDEX IF NOT EXISTS idx_tags_tag ON tags (tag);
            CREATE INDEX IF NOT EXISTS idx_entity_corpora_lookup ON entity_corpora (sha256, collection, architecture, address);
            CREATE INDEX IF NOT EXISTS idx_entity_corpora_corpus ON entity_corpora (corpus);
            CREATE INDEX IF NOT EXISTS idx_entity_children_lookup ON entity_children (sha256, architecture, parent_collection, parent_address, child_collection);
            CREATE INDEX IF NOT EXISTS idx_embedding_counts_lookup ON embedding_counts (collection, architecture, embedding);
            CREATE INDEX IF NOT EXISTS idx_entity_metadata_sha256 ON entity_metadata (sha256);
            CREATE INDEX IF NOT EXISTS idx_entity_metadata_lookup ON entity_metadata (collection, architecture, object_id);
            CREATE INDEX IF NOT EXISTS idx_symbols_symbol ON symbols (symbol);",
        )?;
        match self.sqlite.execute(
            "ALTER TABLE entity_metadata ADD COLUMN markov REAL NULL",
            &[],
        ) {
            Ok(_) => {}
            Err(error) if error.to_string().contains("duplicate column name") => {}
            Err(error) => return Err(error.into()),
        }
        self.ensure_reserved_auth_objects()?;
        Ok(())
    }

    fn ensure_reserved_auth_objects(&self) -> Result<(), Error> {
        let now = chrono::Utc::now().to_rfc3339();
        for role in ["anonymous", "admin", "user"] {
            if self.role_get(role)?.is_none() {
                self.role_create(role, Some(&now))?;
            }
        }
        if self.user_get("anonymous")?.is_none() {
            let _ = self.user_create_with_key(
                "anonymous",
                "anonymous",
                &generate_api_key(),
                true,
                Some(&now),
            )?;
        }
        Ok(())
    }

    pub fn user_create_with_key(
        &self,
        username: &str,
        role: &str,
        api_key: &str,
        reserved: bool,
        timestamp: Option<&str>,
    ) -> Result<UserRecord, Error> {
        let username = normalize_username(username)?;
        let role = normalize_role_name(role)?;
        let api_key = api_key.trim();
        if api_key.is_empty() {
            return Err(Error("api_key must not be empty".to_string()));
        }
        if self.role_get(role)?.is_none() {
            return Err(Error(format!("role {} does not exist", role)));
        }
        if self.user_get(username)?.is_some() {
            return Err(Error(format!("user {} already exists", username)));
        }
        let record = UserRecord {
            username: username.to_string(),
            role: role.to_string(),
            enabled: true,
            reserved,
            timestamp: timestamp
                .map(ToString::to_string)
                .unwrap_or_else(|| chrono::Utc::now().to_rfc3339()),
        };
        self.sqlite.execute(
            "INSERT INTO users (username, role, api_key, enabled, reserved, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            &[
                SQLiteValue::Text(record.username.clone()),
                SQLiteValue::Text(record.role.clone()),
                SQLiteValue::Text(hash_api_key(api_key)),
                SQLiteValue::Integer(if record.enabled { 1 } else { 0 }),
                SQLiteValue::Integer(if record.reserved { 1 } else { 0 }),
                SQLiteValue::Text(record.timestamp.clone()),
            ],
        )?;
        Ok(record)
    }
}

fn generate_secret() -> String {
    let mut bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut bytes);
    crate::hex::encode(&bytes)
}

fn generate_api_key() -> String {
    generate_secret()
}

fn generate_token_id() -> String {
    let mut bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!(
        "tok_{:x}_{}",
        chrono::Utc::now().timestamp_micros(),
        crate::hex::encode(&bytes)
    )
}

fn hash_secret(value: &str) -> String {
    crate::hex::encode(digest(&SHA256, value.as_bytes()).as_ref())
}

fn hash_api_key(value: &str) -> String {
    hash_secret(value)
}

fn normalize_username(value: &str) -> Result<&str, Error> {
    let value = value.trim();
    if value.is_empty() {
        return Err(Error("username must not be empty".to_string()));
    }
    Ok(value)
}

fn normalize_role_name(value: &str) -> Result<&str, Error> {
    let value = value.trim();
    if value.is_empty() {
        return Err(Error("role must not be empty".to_string()));
    }
    Ok(value)
}

fn is_reserved_role(value: &str) -> bool {
    matches!(value, "anonymous" | "admin" | "user")
}

fn user_record_from_row(
    row: serde_json::Map<String, serde_json::Value>,
) -> Result<UserRecord, Error> {
    Ok(UserRecord {
        username: row
            .get("username")
            .and_then(|value| value.as_str())
            .ok_or_else(|| Error("user row is missing username".to_string()))?
            .to_string(),
        role: row
            .get("role")
            .and_then(|value| value.as_str())
            .ok_or_else(|| Error("user row is missing role".to_string()))?
            .to_string(),
        enabled: row
            .get("enabled")
            .and_then(|value| value.as_i64())
            .map(|value| value != 0)
            .ok_or_else(|| Error("user row is missing enabled".to_string()))?,
        reserved: row
            .get("reserved")
            .and_then(|value| value.as_i64())
            .map(|value| value != 0)
            .ok_or_else(|| Error("user row is missing reserved".to_string()))?,
        timestamp: row
            .get("timestamp")
            .and_then(|value| value.as_str())
            .ok_or_else(|| Error("user row is missing timestamp".to_string()))?
            .to_string(),
    })
}

fn entity_metadata_from_row(
    row: serde_json::Map<String, serde_json::Value>,
) -> Result<EntityMetadataRecord, Error> {
    let vector = serde_json::from_value::<Vec<f32>>(
        row.get("vector_json")
            .cloned()
            .ok_or_else(|| Error("entity metadata row is missing vector_json".to_string()))?,
    )
    .or_else(|_| {
        row.get("vector_json")
            .and_then(|value| value.as_str())
            .ok_or_else(|| Error("entity metadata row is missing vector_json".to_string()))
            .and_then(|value| {
                serde_json::from_str::<Vec<f32>>(value).map_err(|error| Error(error.to_string()))
            })
    })?;
    let attributes = serde_json::from_value::<Vec<serde_json::Value>>(
        row.get("attributes_json")
            .cloned()
            .ok_or_else(|| Error("entity metadata row is missing attributes_json".to_string()))?,
    )
    .or_else(|_| {
        row.get("attributes_json")
            .and_then(|value| value.as_str())
            .ok_or_else(|| Error("entity metadata row is missing attributes_json".to_string()))
            .and_then(|value| {
                serde_json::from_str::<Vec<serde_json::Value>>(value)
                    .map_err(|error| Error(error.to_string()))
            })
    })?;
    Ok(EntityMetadataRecord {
        object_id: row
            .get("object_id")
            .and_then(|value| value.as_str())
            .ok_or_else(|| Error("entity metadata row is missing object_id".to_string()))?
            .to_string(),
        sha256: row
            .get("sha256")
            .and_then(|value| value.as_str())
            .ok_or_else(|| Error("entity metadata row is missing sha256".to_string()))?
            .to_string(),
        collection: row
            .get("collection")
            .and_then(|value| value.as_str())
            .ok_or_else(|| Error("entity metadata row is missing collection".to_string()))
            .and_then(parse_collection)?,
        architecture: row
            .get("architecture")
            .and_then(|value| value.as_str())
            .ok_or_else(|| Error("entity metadata row is missing architecture".to_string()))?
            .to_string(),
        username: row
            .get("username")
            .and_then(|value| value.as_str())
            .ok_or_else(|| Error("entity metadata row is missing username".to_string()))?
            .to_string(),
        address: row
            .get("address")
            .and_then(|value| value.as_u64())
            .ok_or_else(|| Error("entity metadata row is missing address".to_string()))?,
        size: row
            .get("size")
            .and_then(|value| value.as_u64())
            .ok_or_else(|| Error("entity metadata row is missing size".to_string()))?,
        cyclomatic_complexity: row
            .get("cyclomatic_complexity")
            .and_then(|value| value.as_u64()),
        average_instructions_per_block: row
            .get("average_instructions_per_block")
            .and_then(|value| value.as_f64()),
        number_of_instructions: row
            .get("number_of_instructions")
            .and_then(|value| value.as_u64()),
        number_of_blocks: row.get("number_of_blocks").and_then(|value| value.as_u64()),
        markov: row.get("markov").and_then(|value| value.as_f64()),
        entropy: row.get("entropy").and_then(|value| value.as_f64()),
        contiguous: row
            .get("contiguous")
            .and_then(|value| value.as_i64())
            .map(|value| value != 0),
        chromosome_entropy: row
            .get("chromosome_entropy")
            .and_then(|value| value.as_f64()),
        timestamp: row
            .get("timestamp")
            .and_then(|value| value.as_str())
            .ok_or_else(|| Error("entity metadata row is missing timestamp".to_string()))?
            .to_string(),
        vector,
        attributes,
    })
}

fn parse_collection(value: &str) -> Result<Collection, Error> {
    match value.trim().to_ascii_lowercase().as_str() {
        "instruction" => Ok(Collection::Instruction),
        "block" => Ok(Collection::Block),
        "function" => Ok(Collection::Function),
        _ => Err(Error(format!("invalid collection {}", value))),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CollectionCommentRecord, CollectionTagRecord, LocalDB, RoleRecord, SampleCommentRecord,
        SampleStatus, SampleStatusRecord, SampleTagRecord,
    };
    use crate::Config;
    use crate::indexing::Collection;

    #[test]
    fn local_db_round_trips_sample_status() {
        let root = tempfile::tempdir().expect("tempdir");
        let mut config = Config::default();
        config.databases.local.path = root.path().join("local.db").display().to_string();
        let db = LocalDB::new(&config).expect("create local db");
        let record = SampleStatusRecord {
            sha256: "d60f9eaa4f62f0ee84531d9aa633c5bb390ea0056953e58d80b9a62277dbe5c5".to_string(),
            status: SampleStatus::Processing,
            timestamp: "2026-03-31T21:00:00Z".to_string(),
            error_message: None,
            id: Some("req_test".to_string()),
        };
        db.sample_status_set(&record).expect("upsert");
        let loaded = db
            .sample_status_get(&record.sha256)
            .expect("get")
            .expect("present");
        assert_eq!(loaded, record);
        db.sample_status_delete(&record.sha256).expect("delete");
        assert!(
            db.sample_status_get(&record.sha256)
                .expect("get after delete")
                .is_none()
        );
    }

    #[test]
    fn local_db_uses_override_path_when_provided() {
        let root = tempfile::tempdir().expect("tempdir");
        let mut config = Config::default();
        config.databases.local.path = root.path().join("configured.db").display().to_string();
        let override_path = root.path().join("override.db");

        let db = LocalDB::with_path(&config, Some(&override_path)).expect("create local db");

        assert_eq!(db.sqlite.path(), override_path.as_path());
    }

    #[test]
    fn local_db_round_trips_tags_and_comments_with_paging() {
        let root = tempfile::tempdir().expect("tempdir");
        let mut config = Config::default();
        config.databases.local.path = root.path().join("local.db").display().to_string();
        let db = LocalDB::new(&config).expect("create local db");
        let sha256 = "d60f9eaa4f62f0ee84531d9aa633c5bb390ea0056953e58d80b9a62277dbe5c5";

        db.sample_tag_add(&SampleTagRecord {
            sha256: sha256.to_string(),
            tag: "goodware".to_string(),
            timestamp: "2026-04-01T00:00:00Z".to_string(),
        })
        .expect("add first tag");
        db.sample_tag_add(&SampleTagRecord {
            sha256: sha256.to_string(),
            tag: "family".to_string(),
            timestamp: "2026-04-01T00:00:01Z".to_string(),
        })
        .expect("add second tag");
        let tags = db
            .sample_tag_search("", 1, 1)
            .expect("search tags page one");
        assert_eq!(tags.items.len(), 1);
        assert!(tags.has_next);
        db.sample_tag_replace(
            sha256,
            &["clean".to_string(), "training".to_string()],
            "2026-04-01T00:00:02Z",
        )
        .expect("replace tags");
        let tags = db
            .sample_tag_search("train", 1, 10)
            .expect("search replaced tags");
        assert_eq!(tags.items.len(), 1);
        assert_eq!(tags.items[0].tag, "training");
        db.sample_tag_remove(sha256, "clean").expect("remove tag");

        db.tag_add("triage", Some("2026-04-01T00:00:03Z"))
            .expect("add catalog tag");
        let tag_catalog = db.tag_search("tri", 10).expect("search tag catalog");
        assert_eq!(tag_catalog.items, vec!["triage".to_string()]);
        assert_eq!(tag_catalog.total_results, 1);

        db.sample_comment_add_record(&SampleCommentRecord {
            sha256: sha256.to_string(),
            comment: "needs review".to_string(),
            timestamp: "2026-04-01T01:00:00Z".to_string(),
        })
        .expect("add comment");
        db.sample_comment_add_record(&SampleCommentRecord {
            sha256: sha256.to_string(),
            comment: "family overlap".to_string(),
            timestamp: "2026-04-01T01:00:01Z".to_string(),
        })
        .expect("add second comment");
        let comments = db
            .sample_comment_search("review", 1, 10)
            .expect("search comments");
        assert_eq!(comments.items.len(), 1);
        assert_eq!(comments.items[0].comment, "needs review");
        db.sample_comment_remove_record(sha256, "needs review")
            .expect("remove comment");
        let comments = db
            .sample_comment_search("review", 1, 10)
            .expect("search comments after delete");
        assert!(comments.items.is_empty());
    }

    #[test]
    fn local_db_round_trips_collection_tags_with_paging() {
        let root = tempfile::tempdir().expect("tempdir");
        let mut config = Config::default();
        config.databases.local.path = root.path().join("local.db").display().to_string();
        let db = LocalDB::new(&config).expect("create local db");
        let sha256 = "d60f9eaa4f62f0ee84531d9aa633c5bb390ea0056953e58d80b9a62277dbe5c5";

        db.collection_tag_add(&CollectionTagRecord {
            sha256: sha256.to_string(),
            collection: Collection::Function,
            address: 0x401000,
            tag: "goodware".to_string(),
            timestamp: "2026-04-02T00:00:00Z".to_string(),
        })
        .expect("add first collection tag");
        db.collection_tag_add(&CollectionTagRecord {
            sha256: sha256.to_string(),
            collection: Collection::Block,
            address: 0x401020,
            tag: "dispatcher".to_string(),
            timestamp: "2026-04-02T00:00:01Z".to_string(),
        })
        .expect("add second collection tag");

        let page = db
            .collection_tag_search("", None, 1, 1)
            .expect("search collection tags page one");
        assert_eq!(page.items.len(), 1);
        assert!(page.has_next);

        let function_tags = db
            .collection_tag_search("good", Some(Collection::Function), 1, 10)
            .expect("search function tags");
        assert_eq!(function_tags.items.len(), 1);
        assert_eq!(function_tags.items[0].address, 0x401000);

        db.collection_tag_replace(
            sha256,
            Collection::Function,
            0x401000,
            &["library".to_string(), "shared".to_string()],
            "2026-04-02T00:00:02Z",
        )
        .expect("replace collection tags");
        let replaced = db
            .collection_tag_search("shared", Some(Collection::Function), 1, 10)
            .expect("search replaced collection tags");
        assert_eq!(replaced.items.len(), 1);
        assert_eq!(replaced.items[0].tag, "shared");

        db.collection_tag_remove(sha256, Collection::Function, 0x401000, "library")
            .expect("remove collection tag");
        let removed = db
            .collection_tag_search("library", Some(Collection::Function), 1, 10)
            .expect("search removed collection tag");
        assert!(removed.items.is_empty());
    }

    #[test]
    fn local_db_round_trips_sample_and_collection_comments_with_optional_timestamps() {
        let root = tempfile::tempdir().expect("tempdir");
        let mut config = Config::default();
        config.databases.local.path = root.path().join("local.db").display().to_string();
        let db = LocalDB::new(&config).expect("create local db");
        let sha256 = "d60f9eaa4f62f0ee84531d9aa633c5bb390ea0056953e58d80b9a62277dbe5c5";

        db.sample_comment_add(sha256, "needs triage", None)
            .expect("add sample comment with default timestamp");
        db.sample_comment_add(sha256, "family overlap", Some("2026-04-02T02:00:00Z"))
            .expect("add sample comment with explicit timestamp");
        let sample_comments = db
            .sample_comment_search("triage", 1, 10)
            .expect("search sample comments");
        assert_eq!(sample_comments.items.len(), 1);
        assert_eq!(sample_comments.items[0].comment, "needs triage");
        assert!(!sample_comments.items[0].timestamp.is_empty());

        db.sample_comment_replace(
            sha256,
            &["reviewed".to_string(), "shared code".to_string()],
            Some("2026-04-02T02:00:01Z"),
        )
        .expect("replace sample comments");
        let replaced_sample_comments = db
            .sample_comment_search("shared", 1, 10)
            .expect("search replaced sample comments");
        assert_eq!(replaced_sample_comments.items.len(), 1);
        assert_eq!(
            replaced_sample_comments.items[0].timestamp,
            "2026-04-02T02:00:01Z"
        );
        db.sample_comment_remove(sha256, "reviewed")
            .expect("remove sample comment");

        db.collection_comment_add(
            sha256,
            Collection::Function,
            0x401000,
            "likely library",
            None,
        )
        .expect("add collection comment with default timestamp");
        db.collection_comment_add(
            sha256,
            Collection::Block,
            0x401020,
            "dispatcher candidate",
            Some("2026-04-02T02:00:02Z"),
        )
        .expect("add collection comment with explicit timestamp");

        let collection_comments = db
            .collection_comment_search("dispatcher", Some(Collection::Block), 1, 10)
            .expect("search collection comments");
        assert_eq!(
            collection_comments.items,
            vec![CollectionCommentRecord {
                sha256: sha256.to_string(),
                collection: Collection::Block,
                address: 0x401020,
                comment: "dispatcher candidate".to_string(),
                timestamp: "2026-04-02T02:00:02Z".to_string(),
            }]
        );

        db.collection_comment_replace(
            sha256,
            Collection::Function,
            0x401000,
            &["crt".to_string(), "shared".to_string()],
            Some("2026-04-02T02:00:03Z"),
        )
        .expect("replace collection comments");
        let replaced_collection_comments = db
            .collection_comment_search("shared", Some(Collection::Function), 1, 10)
            .expect("search replaced collection comments");
        assert_eq!(replaced_collection_comments.items.len(), 1);
        assert_eq!(
            replaced_collection_comments.items[0].timestamp,
            "2026-04-02T02:00:03Z"
        );

        db.collection_comment_remove(sha256, Collection::Function, 0x401000, "crt")
            .expect("remove collection comment");
        let removed_collection_comments = db
            .collection_comment_search("crt", Some(Collection::Function), 1, 10)
            .expect("search removed collection comment");
        assert!(removed_collection_comments.items.is_empty());
    }

    #[test]
    fn local_db_round_trips_roles_and_users() {
        let root = tempfile::tempdir().expect("tempdir");
        let mut config = Config::default();
        config.databases.local.path = root.path().join("local.db").display().to_string();
        let db = LocalDB::new(&config).expect("create local db");

        let anonymous = db
            .user_get("anonymous")
            .expect("get anonymous")
            .expect("anonymous present");
        assert!(anonymous.reserved);
        assert_eq!(anonymous.role, "anonymous");

        let analyst = db
            .role_create("analyst", Some("2026-04-03T10:00:00Z"))
            .expect("create role");
        assert_eq!(
            db.role_get("analyst").expect("get role"),
            Some(RoleRecord {
                name: "analyst".to_string(),
                timestamp: "2026-04-03T10:00:00Z".to_string(),
            })
        );

        let roles = db.role_search("analys", 1, 10).expect("search roles");
        assert_eq!(roles.items, vec![analyst]);

        let (user, plaintext) = db
            .user_create("researcher1", "analyst", Some("2026-04-03T10:00:01Z"))
            .expect("create user");
        assert_eq!(user.username, "researcher1");
        assert_eq!(user.role, "analyst");
        assert!(user.enabled);
        assert!(!user.reserved);
        assert!(db.auth_check(&plaintext).expect("auth check"));
        assert_eq!(
            db.auth_user(&plaintext)
                .expect("auth user")
                .expect("user exists")
                .username,
            "researcher1"
        );

        let reset = db
            .user_reset("researcher1", Some("2026-04-03T10:00:02Z"))
            .expect("reset user");
        assert_ne!(reset, plaintext);
        assert!(!db.auth_check(&plaintext).expect("old key invalid"));
        assert!(db.auth_check(&reset).expect("new key valid"));

        assert!(db.user_disable("researcher1").expect("disable user"));
        assert!(!db.auth_check(&reset).expect("disabled user invalid"));

        assert!(db.user_enable("researcher1").expect("enable user"));
        assert!(db.auth_check(&reset).expect("re-enabled user valid"));

        let users = db.user_search("research", 1, 10).expect("search users");
        assert_eq!(users.items.len(), 1);
        assert_eq!(users.items[0].username, "researcher1");

        assert!(db.role_delete("analyst").is_err());
        assert!(db.user_disable("anonymous").is_err());
        assert!(db.user_reset("anonymous", None).is_err());
    }

    #[test]
    fn local_db_round_trips_tokens() {
        let root = tempfile::tempdir().expect("tempdir");
        let mut config = Config::default();
        config.databases.local.path = root.path().join("local.db").display().to_string();
        let db = LocalDB::new(&config).expect("create local db");

        let (record, plaintext) = db.token_create(900).expect("create token");
        assert_ne!(record.token, plaintext);
        assert!(db.token_check(&plaintext).expect("check correct token"));
        assert!(!db.token_check("wrong").expect("check wrong token"));
        assert!(db.token_disable(&record.id).expect("disable token"));
        assert!(!db.token_check(&plaintext).expect("check disabled token"));
    }

    #[test]
    fn local_db_clears_expired_tokens() {
        let root = tempfile::tempdir().expect("tempdir");
        let mut config = Config::default();
        config.databases.local.path = root.path().join("local.db").display().to_string();
        let db = LocalDB::new(&config).expect("create local db");

        let (_record, plaintext) = db.token_create(0).expect("create token");
        assert_eq!(db.token_clear().expect("clear expired tokens"), 1);
        assert!(!db.token_check(&plaintext).expect("expired token removed"));
    }
}
