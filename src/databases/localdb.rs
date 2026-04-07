use crate::Config;
use crate::databases::sqlite::{Error as SQLiteError, SQLite, SQLiteValue};
use crate::indexing::Collection;
use rand::RngCore;
use ring::digest::{SHA256, digest};
use ring::pbkdf2;
use rusqlite::params_from_iter;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::num::NonZeroU32;
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
    pub username: String,
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
pub struct EntityCommentRecord {
    pub id: i64,
    pub sha256: String,
    pub collection: Collection,
    pub address: u64,
    pub username: String,
    pub comment: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntityCommentSearchPage {
    pub items: Vec<EntityCommentRecord>,
    pub page: usize,
    pub page_size: usize,
    pub total_results: usize,
    pub has_next: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolRecord {
    pub symbol: String,
    pub username: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusRecord {
    pub corpus: String,
    pub username: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolSearchPage {
    pub items: Vec<SymbolRecord>,
    pub total_results: usize,
    pub has_next: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TagCatalogRecord {
    pub tag: String,
    pub username: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TagCatalogSearchPage {
    pub items: Vec<TagCatalogRecord>,
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
    pub collection_tag_count: u64,
    pub collection_tags: Vec<String>,
    pub collection_comment_count: u64,
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
    pub username: String,
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
    pub api_key: String,
    pub role: String,
    pub enabled: bool,
    pub reserved: bool,
    pub profile_picture: Option<String>,
    pub two_factor_enabled: bool,
    pub two_factor_required: bool,
    pub timestamp: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryCodeRecord {
    pub username: String,
    pub code_hash: String,
    pub enabled: bool,
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
pub struct SessionRecord {
    pub id: String,
    pub username: String,
    pub enabled: bool,
    pub timestamp: String,
    pub expires: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginChallengeRecord {
    pub id: String,
    pub username: String,
    pub setup_required: bool,
    pub enabled: bool,
    pub timestamp: String,
    pub expires: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptchaRecord {
    pub id: String,
    pub answer_hash: String,
    pub used: bool,
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

    pub fn sample_tag_add(&self, tag: &SampleTagRecord) -> Result<(), Error> {
        let tag_name = normalize_metadata_name("tag", &tag.tag)?;
        self.sqlite.execute(
            "INSERT INTO sample_tags (sha256, tag, timestamp)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(sha256, tag) DO UPDATE SET
               timestamp = excluded.timestamp",
            &[
                SQLiteValue::Text(tag.sha256.clone()),
                SQLiteValue::Text(tag_name),
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

    pub fn tag_add(
        &self,
        tag: &str,
        timestamp: Option<&str>,
        username: Option<&str>,
    ) -> Result<(), Error> {
        let tag = normalize_metadata_name("tag", tag)?;
        let timestamp = timestamp
            .map(ToString::to_string)
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
        let username = username.unwrap_or_default().trim().to_string();
        self.sqlite.execute(
            "INSERT INTO tags (tag, username, timestamp)
             VALUES (?1, ?2, ?3)
            ON CONFLICT(tag) DO UPDATE SET
              username = excluded.username,
              timestamp = excluded.timestamp",
            &[
                SQLiteValue::Text(tag),
                SQLiteValue::Text(username),
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
            "SELECT tag, username, timestamp
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
            .map(|row| -> Result<TagCatalogRecord, Error> {
                Ok(TagCatalogRecord {
                    tag: row
                        .get("tag")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| Error("tag row is missing tag".to_string()))?
                        .to_string(),
                    username: row
                        .get("username")
                        .and_then(|value| value.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    timestamp: row
                        .get("timestamp")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| Error("tag row is missing timestamp".to_string()))?
                        .to_string(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(TagCatalogSearchPage {
            has_next: total_results > items.len(),
            total_results,
            items,
        })
    }

    pub fn tag_get(&self, tag: &str) -> Result<Option<TagCatalogRecord>, Error> {
        let rows = self.sqlite.query(
            "SELECT tag, username, timestamp
             FROM tags
             WHERE tag = ?1
             LIMIT 1",
            &[SQLiteValue::Text(tag.trim().to_string())],
        )?;
        rows.into_iter()
            .next()
            .map(|row| {
                Ok(TagCatalogRecord {
                    tag: row
                        .get("tag")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| Error("tag row is missing tag".to_string()))?
                        .to_string(),
                    username: row
                        .get("username")
                        .and_then(|value| value.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    timestamp: row
                        .get("timestamp")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| Error("tag row is missing timestamp".to_string()))?
                        .to_string(),
                })
            })
            .transpose()
    }

    pub fn tag_delete_global(&self, tag: &str) -> Result<bool, Error> {
        let tag = normalize_metadata_name("tag", tag)?;
        self.sqlite.execute(
            "DELETE FROM sample_tags WHERE tag = ?1",
            &[SQLiteValue::Text(tag.clone())],
        )?;
        self.sqlite.execute(
            "DELETE FROM collection_tags WHERE tag = ?1",
            &[SQLiteValue::Text(tag.clone())],
        )?;
        self.sqlite.execute(
            "DELETE FROM tags WHERE tag = ?1",
            &[SQLiteValue::Text(tag.clone())],
        )?;
        let rows = self.sqlite.query(
            "SELECT tag FROM tags WHERE tag = ?1 LIMIT 1",
            &[SQLiteValue::Text(tag)],
        )?;
        Ok(rows.is_empty())
    }

    pub fn collection_tag_add(&self, tag: &CollectionTagRecord) -> Result<(), Error> {
        self.tag_add(&tag.tag, Some(&tag.timestamp), Some(&tag.username))?;
        self.sqlite.execute(
            "INSERT INTO collection_tags (sha256, collection, address, tag, username, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(sha256, collection, address, tag) DO UPDATE SET
               username = excluded.username,
               timestamp = excluded.timestamp",
            &[
                SQLiteValue::Text(tag.sha256.clone()),
                SQLiteValue::Text(tag.collection.as_str().to_string()),
                SQLiteValue::Integer(tag.address as i64),
                SQLiteValue::Text(tag.tag.clone()),
                SQLiteValue::Text(tag.username.clone()),
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
                "INSERT INTO tags (tag, username, timestamp)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(tag) DO UPDATE SET
                   username = excluded.username,
                   timestamp = excluded.timestamp",
            )?;
            let mut collection_tag_upsert = transaction.prepare(
                "INSERT INTO collection_tags (sha256, collection, address, tag, username, timestamp)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(sha256, collection, address, tag) DO UPDATE SET
                   username = excluded.username,
                   timestamp = excluded.timestamp",
            )?;

            for record in tags {
                let tag = normalize_metadata_name("tag", &record.tag)?;
                tag_upsert.execute((&tag, &record.username, &record.timestamp))?;
                collection_tag_upsert.execute((
                    &record.sha256,
                    record.collection.as_str(),
                    record.address as i64,
                    &tag,
                    &record.username,
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
        username: &str,
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
                username: username.to_string(),
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
        self.collection_tag_details_list(sha256, collection, address)
            .map(|items| items.into_iter().map(|item| item.tag).collect())
    }

    pub fn collection_tag_details_list(
        &self,
        sha256: &str,
        collection: Collection,
        address: u64,
    ) -> Result<Vec<CollectionTagRecord>, Error> {
        let rows = self.sqlite.query(
            "SELECT tag, username, timestamp
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
                Ok(CollectionTagRecord {
                    sha256: sha256.to_string(),
                    collection,
                    address,
                    tag: row
                        .get("tag")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| Error("collection tag row is missing tag".to_string()))?
                        .to_string(),
                    username: row
                        .get("username")
                        .and_then(|value| value.as_str())
                        .unwrap_or_default()
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
                "SELECT sha256, collection, address, tag, username, timestamp
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
                    username: row
                        .get("username")
                        .and_then(|value| value.as_str())
                        .unwrap_or_default()
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

    pub fn entity_comment_add(
        &self,
        sha256: &str,
        collection: Collection,
        address: u64,
        username: &str,
        comment: &str,
        timestamp: Option<&str>,
    ) -> Result<EntityCommentRecord, Error> {
        let comment = comment.trim();
        if comment.is_empty() {
            return Err(Error("comment must not be empty".to_string()));
        }
        if comment.chars().count() > 2048 {
            return Err(Error("comment must be at most 2048 characters".to_string()));
        }
        let timestamp = timestamp
            .map(ToString::to_string)
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
        let username = username.trim().to_string();
        let mut rows = self.sqlite.query(
            "INSERT INTO entity_comments (sha256, collection, address, username, comment, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             RETURNING id, sha256, collection, address, username, comment, timestamp",
            &[
                SQLiteValue::Text(sha256.to_string()),
                SQLiteValue::Text(collection.as_str().to_string()),
                SQLiteValue::Integer(address as i64),
                SQLiteValue::Text(username),
                SQLiteValue::Text(comment.to_string()),
                SQLiteValue::Text(timestamp),
            ],
        )?;
        let row = rows
            .pop()
            .ok_or_else(|| Error("entity comment insert did not return a row".to_string()))?;
        self.entity_comment_record_from_row(row)
    }

    pub fn entity_comment_delete(&self, id: i64) -> Result<Option<EntityCommentRecord>, Error> {
        if id <= 0 {
            return Err(Error("comment id must be positive".to_string()));
        }
        let mut rows = self.sqlite.query(
            "DELETE FROM entity_comments
             WHERE id = ?1
             RETURNING id, sha256, collection, address, username, comment, timestamp",
            &[SQLiteValue::Integer(id)],
        )?;
        rows.pop()
            .map(|row| self.entity_comment_record_from_row(row))
            .transpose()
    }

    pub fn entity_comment_count(
        &self,
        sha256: &str,
        collection: Collection,
        address: u64,
    ) -> Result<usize, Error> {
        let rows = self.sqlite.query(
            "SELECT COUNT(*) AS count
             FROM entity_comments
             WHERE sha256 = ?1 AND collection = ?2 AND address = ?3",
            &[
                SQLiteValue::Text(sha256.to_string()),
                SQLiteValue::Text(collection.as_str().to_string()),
                SQLiteValue::Integer(address as i64),
            ],
        )?;
        Ok(rows
            .into_iter()
            .next()
            .and_then(|row| row.get("count").and_then(|value| value.as_i64()))
            .unwrap_or(0)
            .max(0) as usize)
    }

    pub fn entity_comment_counts(
        &self,
        keys: &[(String, Collection, u64)],
    ) -> Result<BTreeMap<(String, Collection, u64), usize>, Error> {
        let mut counts = BTreeMap::new();
        if keys.is_empty() {
            return Ok(counts);
        }
        let mut sql = String::from(
            "SELECT sha256, collection, address, COUNT(*) AS count
             FROM entity_comments
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
                .ok_or_else(|| Error("entity comment count row is missing sha256".to_string()))?
                .to_string();
            let collection = row
                .get("collection")
                .and_then(|value| value.as_str())
                .ok_or_else(|| Error("entity comment count row is missing collection".to_string()))
                .and_then(parse_collection)?;
            let address = row
                .get("address")
                .and_then(|value| value.as_i64())
                .ok_or_else(|| Error("entity comment count row is missing address".to_string()))?
                .max(0) as u64;
            let count = row
                .get("count")
                .and_then(|value| value.as_i64())
                .ok_or_else(|| Error("entity comment count row is missing count".to_string()))?
                .max(0) as usize;
            counts.insert((sha256, collection, address), count);
        }
        Ok(counts)
    }

    pub fn entity_comment_list(
        &self,
        sha256: &str,
        collection: Collection,
        address: u64,
        page: usize,
        page_size: usize,
    ) -> Result<EntityCommentSearchPage, Error> {
        let page = page.max(1);
        let page_size = page_size.max(1);
        let offset = (page - 1) * page_size;
        let limit = page_size + 1;
        let total_rows = self.sqlite.query(
            "SELECT COUNT(*) AS count
             FROM entity_comments
             WHERE sha256 = ?1 AND collection = ?2 AND address = ?3",
            &[
                SQLiteValue::Text(sha256.to_string()),
                SQLiteValue::Text(collection.as_str().to_string()),
                SQLiteValue::Integer(address as i64),
            ],
        )?;
        let total_results = total_rows
            .into_iter()
            .next()
            .and_then(|row| row.get("count").and_then(|value| value.as_i64()))
            .unwrap_or(0)
            .max(0) as usize;
        let rows = self.sqlite.query(
            "SELECT id, sha256, collection, address, username, comment, timestamp
             FROM entity_comments
             WHERE sha256 = ?1 AND collection = ?2 AND address = ?3
             ORDER BY timestamp DESC, id DESC
             LIMIT ?4 OFFSET ?5",
            &[
                SQLiteValue::Text(sha256.to_string()),
                SQLiteValue::Text(collection.as_str().to_string()),
                SQLiteValue::Integer(address as i64),
                SQLiteValue::Integer(limit as i64),
                SQLiteValue::Integer(offset as i64),
            ],
        )?;
        let has_next = rows.len() > page_size;
        let items = rows
            .into_iter()
            .take(page_size)
            .map(|row| self.entity_comment_record_from_row(row))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(EntityCommentSearchPage {
            items,
            page,
            page_size,
            total_results,
            has_next,
        })
    }

    pub fn entity_comment_search(
        &self,
        query: &str,
        page: usize,
        page_size: usize,
    ) -> Result<EntityCommentSearchPage, Error> {
        let page = page.max(1);
        let page_size = page_size.max(1);
        let offset = (page - 1) * page_size;
        let limit = page_size + 1;
        let needle = query.trim().to_ascii_lowercase();
        let pattern = if needle.is_empty() {
            "%".to_string()
        } else {
            format!("%{}%", needle)
        };
        let total_rows = self.sqlite.query(
            "SELECT COUNT(*) AS count
             FROM entity_comments
             WHERE LOWER(comment) LIKE ?1
                OR LOWER(username) LIKE ?1
                OR LOWER(sha256) LIKE ?1
                OR LOWER(collection) LIKE ?1
                OR LOWER(printf('0x%x', address)) LIKE ?1
                OR LOWER(CAST(address AS TEXT)) LIKE ?1",
            &[SQLiteValue::Text(pattern.clone())],
        )?;
        let total_results = total_rows
            .into_iter()
            .next()
            .and_then(|row| row.get("count").and_then(|value| value.as_i64()))
            .unwrap_or(0)
            .max(0) as usize;
        let rows = self.sqlite.query(
            "SELECT id, sha256, collection, address, username, comment, timestamp
             FROM entity_comments
             WHERE LOWER(comment) LIKE ?1
                OR LOWER(username) LIKE ?1
                OR LOWER(sha256) LIKE ?1
                OR LOWER(collection) LIKE ?1
                OR LOWER(printf('0x%x', address)) LIKE ?1
                OR LOWER(CAST(address AS TEXT)) LIKE ?1
             ORDER BY timestamp DESC, id DESC
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
            .map(|row| self.entity_comment_record_from_row(row))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(EntityCommentSearchPage {
            items,
            page,
            page_size,
            total_results,
            has_next,
        })
    }

    fn entity_comment_record_from_row(
        &self,
        row: serde_json::Map<String, serde_json::Value>,
    ) -> Result<EntityCommentRecord, Error> {
        Ok(EntityCommentRecord {
            id: row
                .get("id")
                .and_then(|value| value.as_i64())
                .ok_or_else(|| Error("entity comment row is missing id".to_string()))?,
            sha256: row
                .get("sha256")
                .and_then(|value| value.as_str())
                .ok_or_else(|| Error("entity comment row is missing sha256".to_string()))?
                .to_string(),
            collection: row
                .get("collection")
                .and_then(|value| value.as_str())
                .ok_or_else(|| Error("entity comment row is missing collection".to_string()))
                .and_then(parse_collection)?,
            address: row
                .get("address")
                .and_then(|value| value.as_u64())
                .ok_or_else(|| Error("entity comment row is missing address".to_string()))?,
            username: row
                .get("username")
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_string(),
            comment: row
                .get("comment")
                .and_then(|value| value.as_str())
                .ok_or_else(|| Error("entity comment row is missing comment".to_string()))?
                .to_string(),
            timestamp: row
                .get("timestamp")
                .and_then(|value| value.as_str())
                .ok_or_else(|| Error("entity comment row is missing timestamp".to_string()))?
                .to_string(),
        })
    }

    pub fn symbol_add(
        &self,
        symbol: &str,
        timestamp: Option<&str>,
        username: Option<&str>,
    ) -> Result<(), Error> {
        let symbol = normalize_metadata_name("symbol", symbol)?;
        let timestamp = timestamp
            .map(ToString::to_string)
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
        let username = username.unwrap_or_default().trim().to_string();
        self.sqlite.execute(
            "INSERT INTO symbols (symbol, username, timestamp)
             VALUES (?1, ?2, ?3)
            ON CONFLICT(symbol) DO UPDATE SET
              username = excluded.username,
              timestamp = excluded.timestamp",
            &[
                SQLiteValue::Text(symbol),
                SQLiteValue::Text(username),
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
            "SELECT symbol, username, timestamp
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
            .map(|row| -> Result<SymbolRecord, Error> {
                Ok(SymbolRecord {
                    symbol: row
                        .get("symbol")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| Error("symbol row is missing symbol".to_string()))?
                        .to_string(),
                    username: row
                        .get("username")
                        .and_then(|value| value.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    timestamp: row
                        .get("timestamp")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| Error("symbol row is missing timestamp".to_string()))?
                        .to_string(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(SymbolSearchPage {
            has_next: total_results > items.len(),
            total_results,
            items,
        })
    }

    pub fn symbol_get(&self, symbol: &str) -> Result<Option<SymbolRecord>, Error> {
        let rows = self.sqlite.query(
            "SELECT symbol, username, timestamp
             FROM symbols
             WHERE symbol = ?1
             LIMIT 1",
            &[SQLiteValue::Text(symbol.trim().to_string())],
        )?;
        rows.into_iter()
            .next()
            .map(|row| {
                Ok(SymbolRecord {
                    symbol: row
                        .get("symbol")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| Error("symbol row is missing symbol".to_string()))?
                        .to_string(),
                    username: row
                        .get("username")
                        .and_then(|value| value.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    timestamp: row
                        .get("timestamp")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| Error("symbol row is missing timestamp".to_string()))?
                        .to_string(),
                })
            })
            .transpose()
    }

    pub fn symbol_delete_global(&self, symbol: &str) -> Result<bool, Error> {
        let symbol = normalize_metadata_name("symbol", symbol)?;
        self.sqlite.execute(
            "DELETE FROM symbols WHERE symbol = ?1",
            &[SQLiteValue::Text(symbol.clone())],
        )?;
        let rows = self.sqlite.query(
            "SELECT symbol FROM symbols WHERE symbol = ?1 LIMIT 1",
            &[SQLiteValue::Text(symbol)],
        )?;
        Ok(rows.is_empty())
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
    ) -> Result<(UserRecord, String, Vec<String>), Error> {
        self.user_create_account(
            username,
            &generate_password_secret(),
            role,
            false,
            false,
            timestamp,
        )
    }

    pub fn user_create_account(
        &self,
        username: &str,
        password: &str,
        role: &str,
        reserved: bool,
        two_factor_required: bool,
        timestamp: Option<&str>,
    ) -> Result<(UserRecord, String, Vec<String>), Error> {
        let username = normalize_username(username)?;
        let role = normalize_role_name(role)?;
        normalize_password(password)?;
        if self.role_get(role)?.is_none() {
            return Err(Error(format!("role {} does not exist", role)));
        }
        if self.user_get(&username)?.is_some() {
            return Err(Error(format!("user {} already exists", username)));
        }
        let api_key = generate_api_key();
        let recovery_codes = generate_recovery_codes();
        let when = timestamp
            .map(ToString::to_string)
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
        let record = UserRecord {
            username: username.to_string(),
            api_key: api_key.clone(),
            role: role.to_string(),
            enabled: true,
            reserved,
            profile_picture: None,
            two_factor_enabled: false,
            two_factor_required,
            timestamp: when.clone(),
        };
        self.sqlite.execute(
            "INSERT INTO users (username, email, password_hash, role, api_key, enabled, reserved, profile_picture, two_factor_enabled, two_factor_required, two_factor_secret, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            &[
                SQLiteValue::Text(record.username.clone()),
                SQLiteValue::Text(String::new()),
                SQLiteValue::Text(hash_password(password)?),
                SQLiteValue::Text(record.role.clone()),
                SQLiteValue::Text(record.api_key.clone()),
                SQLiteValue::Integer(if record.enabled { 1 } else { 0 }),
                SQLiteValue::Integer(if record.reserved { 1 } else { 0 }),
                match &record.profile_picture {
                    Some(value) => SQLiteValue::Text(value.clone()),
                    None => SQLiteValue::Null,
                },
                SQLiteValue::Integer(if record.two_factor_enabled { 1 } else { 0 }),
                SQLiteValue::Integer(if record.two_factor_required { 1 } else { 0 }),
                SQLiteValue::Null,
                SQLiteValue::Text(record.timestamp.clone()),
            ],
        )?;
        self.replace_recovery_codes(&record.username, &recovery_codes, &when)?;
        Ok((record, api_key, recovery_codes))
    }

    pub fn user_count(&self) -> Result<usize, Error> {
        let rows = self
            .sqlite
            .query("SELECT COUNT(*) AS count FROM users", &[])?;
        Ok(rows
            .into_iter()
            .next()
            .and_then(|row| row.get("count").and_then(|value| value.as_i64()))
            .unwrap_or(0) as usize)
    }

    pub fn username_availability(&self, username: &str) -> Result<(String, bool), Error> {
        let normalized = normalize_username(username)?;
        let available = self.user_get(&normalized)?.is_none();
        Ok((normalized, available))
    }

    pub fn admin_count(&self) -> Result<usize, Error> {
        let rows = self.sqlite.query(
            "SELECT COUNT(*) AS count FROM users WHERE role = 'admin'",
            &[],
        )?;
        Ok(rows
            .into_iter()
            .next()
            .and_then(|row| row.get("count").and_then(|value| value.as_i64()))
            .unwrap_or(0) as usize)
    }

    pub fn enabled_admin_count(&self) -> Result<usize, Error> {
        let rows = self.sqlite.query(
            "SELECT COUNT(*) AS count FROM users WHERE role = 'admin' AND enabled = 1",
            &[],
        )?;
        Ok(rows
            .into_iter()
            .next()
            .and_then(|row| row.get("count").and_then(|value| value.as_i64()))
            .unwrap_or(0) as usize)
    }

    pub fn user_authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<UserRecord>, Error> {
        let username = normalize_username(username)?;
        if username.is_empty() {
            return Ok(None);
        }
        let rows = self.sqlite.query(
            "SELECT username, email, api_key, role, enabled, reserved, profile_picture, two_factor_enabled, two_factor_required, two_factor_secret, password_hash, timestamp
             FROM users
             WHERE lower(username) = ?1 AND enabled = 1
             LIMIT 1",
            &[SQLiteValue::Text(username)],
        )?;
        let Some(row) = rows.into_iter().next() else {
            return Ok(None);
        };
        let password_hash = row
            .get("password_hash")
            .and_then(|value| value.as_str())
            .ok_or_else(|| Error("user row is missing password_hash".to_string()))?;
        if !verify_password(password_hash, password)? {
            return Ok(None);
        }
        Ok(Some(user_record_from_row(row)?))
    }

    pub fn user_update_role(&self, username: &str, role: &str) -> Result<UserRecord, Error> {
        let username = normalize_username(username)?;
        let role = normalize_role_name(role)?;
        let current = self
            .user_get(&username)?
            .ok_or_else(|| Error(format!("user {} does not exist", username)))?;
        if current.reserved {
            return Err(Error(format!("user {} is reserved", username)));
        }
        if current.role == "admin"
            && current.enabled
            && role != "admin"
            && self.enabled_admin_count()? <= 1
        {
            return Err(Error("cannot remove the last admin role".to_string()));
        }
        self.sqlite.execute(
            "UPDATE users SET role = ?1, timestamp = ?2 WHERE username = ?3",
            &[
                SQLiteValue::Text(role.to_string()),
                SQLiteValue::Text(chrono::Utc::now().to_rfc3339()),
                SQLiteValue::Text(username.to_string()),
            ],
        )?;
        self.user_get(&username)?
            .ok_or_else(|| Error(format!("user {} does not exist", username)))
    }

    pub fn user_update_profile_picture(
        &self,
        username: &str,
        profile_picture: Option<&str>,
    ) -> Result<UserRecord, Error> {
        let username = normalize_username(username)?;
        let current = self
            .user_get(&username)?
            .ok_or_else(|| Error(format!("user {} does not exist", username)))?;
        if current.reserved {
            return Err(Error(format!("user {} is reserved", username)));
        }
        self.sqlite.execute(
            "UPDATE users SET profile_picture = ?1, timestamp = ?2 WHERE username = ?3",
            &[
                match profile_picture
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                {
                    Some(value) => SQLiteValue::Text(value.to_string()),
                    None => SQLiteValue::Null,
                },
                SQLiteValue::Text(chrono::Utc::now().to_rfc3339()),
                SQLiteValue::Text(username.to_string()),
            ],
        )?;
        self.user_get(&username)?
            .ok_or_else(|| Error(format!("user {} does not exist", username)))
    }

    pub fn user_begin_two_factor_setup(
        &self,
        username: &str,
        secret: &str,
    ) -> Result<UserRecord, Error> {
        let username = normalize_username(username)?;
        let current = self
            .user_get(&username)?
            .ok_or_else(|| Error(format!("user {} does not exist", username)))?;
        if !current.enabled {
            return Err(Error(format!("user {} is disabled", username)));
        }
        self.sqlite.execute(
            "UPDATE users
             SET two_factor_secret = ?1,
                 two_factor_enabled = 0,
                 timestamp = ?2
             WHERE username = ?3",
            &[
                SQLiteValue::Text(secret.trim().to_string()),
                SQLiteValue::Text(chrono::Utc::now().to_rfc3339()),
                SQLiteValue::Text(username.to_string()),
            ],
        )?;
        self.user_get(&username)?
            .ok_or_else(|| Error(format!("user {} does not exist", username)))
    }

    pub fn user_enable_two_factor(
        &self,
        username: &str,
        timestamp: Option<&str>,
    ) -> Result<UserRecord, Error> {
        let username = normalize_username(username)?;
        let current = self
            .user_get(&username)?
            .ok_or_else(|| Error(format!("user {} does not exist", username)))?;
        if !current.enabled {
            return Err(Error(format!("user {} is disabled", username)));
        }
        let rows = self.sqlite.query(
            "SELECT two_factor_secret FROM users WHERE username = ?1 LIMIT 1",
            &[SQLiteValue::Text(username.to_string())],
        )?;
        let Some(row) = rows.into_iter().next() else {
            return Err(Error(format!("user {} does not exist", username)));
        };
        let secret = row
            .get("two_factor_secret")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .trim()
            .to_string();
        if secret.is_empty() {
            return Err(Error("two-factor setup has not been started".to_string()));
        }
        let when = timestamp
            .map(ToString::to_string)
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
        self.sqlite.execute(
            "UPDATE users
             SET two_factor_enabled = 1,
                 timestamp = ?1
             WHERE username = ?2",
            &[
                SQLiteValue::Text(when),
                SQLiteValue::Text(username.to_string()),
            ],
        )?;
        self.user_get(&username)?
            .ok_or_else(|| Error(format!("user {} does not exist", username)))
    }

    pub fn user_two_factor_secret(&self, username: &str) -> Result<Option<String>, Error> {
        let username = normalize_username(username)?;
        let rows = self.sqlite.query(
            "SELECT two_factor_secret FROM users WHERE username = ?1 LIMIT 1",
            &[SQLiteValue::Text(username.to_string())],
        )?;
        Ok(rows
            .into_iter()
            .next()
            .and_then(|row| {
                row.get("two_factor_secret")
                    .and_then(|value| value.as_str())
                    .map(ToString::to_string)
            })
            .filter(|value| !value.trim().is_empty()))
    }

    pub fn user_disable_two_factor(
        &self,
        username: &str,
        clear_required: bool,
        timestamp: Option<&str>,
    ) -> Result<UserRecord, Error> {
        let username = normalize_username(username)?;
        let current = self
            .user_get(&username)?
            .ok_or_else(|| Error(format!("user {} does not exist", username)))?;
        if current.reserved {
            return Err(Error(format!("user {} is reserved", username)));
        }
        let when = timestamp
            .map(ToString::to_string)
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
        self.sqlite.execute(
            "UPDATE users
             SET two_factor_secret = NULL,
                 two_factor_enabled = 0,
                 two_factor_required = ?1,
                 timestamp = ?2
             WHERE username = ?3",
            &[
                SQLiteValue::Integer(if clear_required { 0 } else { 1 }),
                SQLiteValue::Text(when),
                SQLiteValue::Text(username.to_string()),
            ],
        )?;
        self.user_get(&username)?
            .ok_or_else(|| Error(format!("user {} does not exist", username)))
    }

    pub fn user_require_two_factor(
        &self,
        username: &str,
        required: bool,
        timestamp: Option<&str>,
    ) -> Result<UserRecord, Error> {
        let username = normalize_username(username)?;
        let current = self
            .user_get(&username)?
            .ok_or_else(|| Error(format!("user {} does not exist", username)))?;
        if current.reserved {
            return Err(Error(format!("user {} is reserved", username)));
        }
        let when = timestamp
            .map(ToString::to_string)
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
        self.sqlite.execute(
            "UPDATE users SET two_factor_required = ?1, timestamp = ?2 WHERE username = ?3",
            &[
                SQLiteValue::Integer(if required { 1 } else { 0 }),
                SQLiteValue::Text(when),
                SQLiteValue::Text(username.to_string()),
            ],
        )?;
        self.user_get(&username)?
            .ok_or_else(|| Error(format!("user {} does not exist", username)))
    }

    pub fn user_change_password(
        &self,
        username: &str,
        current_password: &str,
        new_password: &str,
    ) -> Result<(), Error> {
        let username = normalize_username(username)?;
        normalize_password(new_password)?;
        let rows = self.sqlite.query(
            "SELECT password_hash FROM users WHERE username = ?1 LIMIT 1",
            &[SQLiteValue::Text(username.to_string())],
        )?;
        let Some(row) = rows.into_iter().next() else {
            return Err(Error(format!("user {} does not exist", username)));
        };
        let password_hash = row
            .get("password_hash")
            .and_then(|value| value.as_str())
            .ok_or_else(|| Error("user row is missing password_hash".to_string()))?;
        if !verify_password(password_hash, current_password)? {
            return Err(Error("current password is invalid".to_string()));
        }
        self.user_set_password(&username, new_password)
    }

    pub fn user_set_password(&self, username: &str, password: &str) -> Result<(), Error> {
        let username = normalize_username(username)?;
        normalize_password(password)?;
        self.sqlite.execute(
            "UPDATE users SET password_hash = ?1, timestamp = ?2 WHERE username = ?3",
            &[
                SQLiteValue::Text(hash_password(password)?),
                SQLiteValue::Text(chrono::Utc::now().to_rfc3339()),
                SQLiteValue::Text(username.to_string()),
            ],
        )?;
        Ok(())
    }

    pub fn user_regenerate_recovery_codes(
        &self,
        username: &str,
        timestamp: Option<&str>,
    ) -> Result<Vec<String>, Error> {
        let username = normalize_username(username)?;
        let current = self
            .user_get(&username)?
            .ok_or_else(|| Error(format!("user {} does not exist", username)))?;
        if current.reserved {
            return Err(Error(format!("user {} is reserved", username)));
        }
        let codes = generate_recovery_codes();
        let when = timestamp
            .map(ToString::to_string)
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
        self.replace_recovery_codes(&username, &codes, &when)?;
        Ok(codes)
    }

    pub fn user_reset_with_recovery_code(
        &self,
        username: &str,
        recovery_code: &str,
        new_password: &str,
        timestamp: Option<&str>,
    ) -> Result<(), Error> {
        let username = normalize_username(username)?;
        normalize_password(new_password)?;
        let current = self
            .user_get(&username)?
            .ok_or_else(|| Error(format!("user {} does not exist", username)))?;
        if !current.enabled {
            return Err(Error(format!("user {} is disabled", username)));
        }
        let _when = self.consume_recovery_code(&username, recovery_code, timestamp)?;
        self.user_set_password(&username, new_password)?;
        Ok(())
    }

    pub fn user_consume_recovery_code(
        &self,
        username: &str,
        recovery_code: &str,
        timestamp: Option<&str>,
    ) -> Result<(), Error> {
        let username = normalize_username(username)?;
        let _ = self.consume_recovery_code(&username, recovery_code, timestamp)?;
        Ok(())
    }

    pub fn user_delete(&self, username: &str) -> Result<bool, Error> {
        let username = normalize_username(username)?;
        let current = self
            .user_get(&username)?
            .ok_or_else(|| Error(format!("user {} does not exist", username)))?;
        if current.reserved {
            return Err(Error(format!("user {} is reserved", username)));
        }
        if current.role == "admin" && current.enabled && self.enabled_admin_count()? <= 1 {
            return Err(Error("cannot delete the last admin".to_string()));
        }
        self.sqlite.execute(
            "DELETE FROM sessions WHERE username = ?1",
            &[SQLiteValue::Text(username.to_string())],
        )?;
        self.sqlite.execute(
            "DELETE FROM login_challenges WHERE username = ?1",
            &[SQLiteValue::Text(username.to_string())],
        )?;
        self.sqlite.execute(
            "DELETE FROM recovery_codes WHERE username = ?1",
            &[SQLiteValue::Text(username.to_string())],
        )?;
        self.sqlite.execute(
            "DELETE FROM users WHERE username = ?1",
            &[SQLiteValue::Text(username.to_string())],
        )?;
        Ok(self.user_get(&username)?.is_none())
    }

    pub fn user_regenerate_key(
        &self,
        username: &str,
        timestamp: Option<&str>,
    ) -> Result<String, Error> {
        let username = normalize_username(username)?;
        let current = self
            .user_get(&username)?
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
                SQLiteValue::Text(plaintext.clone()),
                SQLiteValue::Text(when),
                SQLiteValue::Text(username.to_string()),
            ],
        )?;
        Ok(plaintext)
    }

    pub fn user_disable(&self, username: &str) -> Result<bool, Error> {
        let username = normalize_username(username)?;
        let current = self
            .user_get(&username)?
            .ok_or_else(|| Error(format!("user {} does not exist", username)))?;
        if current.reserved {
            return Err(Error(format!("user {} is reserved", username)));
        }
        if current.role == "admin" && current.enabled && self.enabled_admin_count()? <= 1 {
            return Err(Error("cannot disable the last enabled admin".to_string()));
        }
        self.sqlite.execute(
            "UPDATE users SET enabled = 0, timestamp = ?1 WHERE username = ?2",
            &[
                SQLiteValue::Text(chrono::Utc::now().to_rfc3339()),
                SQLiteValue::Text(username.to_string()),
            ],
        )?;
        self.sqlite.execute(
            "UPDATE sessions SET enabled = 0 WHERE username = ?1",
            &[SQLiteValue::Text(username.to_string())],
        )?;
        self.sqlite.execute(
            "UPDATE login_challenges SET enabled = 0 WHERE username = ?1",
            &[SQLiteValue::Text(username.to_string())],
        )?;
        Ok(true)
    }

    pub fn user_enable(&self, username: &str) -> Result<bool, Error> {
        let username = normalize_username(username)?;
        let current = self
            .user_get(&username)?
            .ok_or_else(|| Error(format!("user {} does not exist", username)))?;
        if current.reserved {
            return Err(Error(format!("user {} is reserved", username)));
        }
        self.sqlite.execute(
            "UPDATE users SET enabled = 1, timestamp = ?1 WHERE username = ?2",
            &[
                SQLiteValue::Text(chrono::Utc::now().to_rfc3339()),
                SQLiteValue::Text(username.to_string()),
            ],
        )?;
        Ok(self.user_get(&username)?.is_some())
    }

    pub fn user_reset(&self, username: &str, timestamp: Option<&str>) -> Result<String, Error> {
        let password = generate_password_secret();
        self.user_set_password(username, &password)?;
        if let Some(when) = timestamp {
            self.sqlite.execute(
                "UPDATE users SET timestamp = ?1 WHERE username = ?2",
                &[
                    SQLiteValue::Text(when.to_string()),
                    SQLiteValue::Text(normalize_username(username)?.to_string()),
                ],
            )?;
        }
        Ok(password)
    }

    pub fn user_get(&self, username: &str) -> Result<Option<UserRecord>, Error> {
        let username = normalize_username(username)?;
        let rows = self.sqlite.query(
            "SELECT username, email, api_key, role, enabled, reserved, profile_picture, two_factor_enabled, two_factor_required, two_factor_secret, timestamp
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
            "SELECT username, email, api_key, role, enabled, reserved, profile_picture, two_factor_enabled, two_factor_required, two_factor_secret, timestamp
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

    pub fn user_search_total(&self, query: &str) -> Result<usize, Error> {
        let like = format!("%{}%", query.trim().to_ascii_lowercase());
        let rows = self.sqlite.query(
            "SELECT COUNT(*) AS count
             FROM users
             WHERE lower(username) LIKE ?1 OR lower(role) LIKE ?1",
            &[SQLiteValue::Text(like)],
        )?;
        Ok(rows
            .into_iter()
            .next()
            .and_then(|row| row.get("count").and_then(|value| value.as_i64()))
            .unwrap_or(0) as usize)
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
            "SELECT username, email, api_key, role, enabled, reserved, profile_picture, two_factor_enabled, two_factor_required, two_factor_secret, timestamp
             FROM users
             WHERE api_key = ?1 AND enabled = 1
             LIMIT 1",
            &[SQLiteValue::Text(api_key.to_string())],
        )?;
        Ok(rows
            .into_iter()
            .next()
            .map(user_record_from_row)
            .transpose()?)
    }

    pub fn session_create(
        &self,
        username: &str,
        ttl_seconds: u64,
    ) -> Result<(SessionRecord, String), Error> {
        let username = normalize_username(username)?;
        let current = self
            .user_get(&username)?
            .ok_or_else(|| Error(format!("user {} does not exist", username)))?;
        if !current.enabled {
            return Err(Error(format!("user {} is disabled", username)));
        }
        let plaintext = generate_secret();
        let now = chrono::Utc::now();
        let expires = now
            .checked_add_signed(chrono::TimeDelta::seconds(ttl_seconds as i64))
            .ok_or_else(|| Error("failed to compute session expiry".to_string()))?;
        let record = SessionRecord {
            id: generate_session_id(),
            username: username.to_string(),
            enabled: true,
            timestamp: now.to_rfc3339(),
            expires: expires.to_rfc3339(),
        };
        self.sqlite.execute(
            "INSERT INTO sessions (id, session, username, enabled, timestamp, expires)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            &[
                SQLiteValue::Text(record.id.clone()),
                SQLiteValue::Text(hash_secret(&plaintext)),
                SQLiteValue::Text(record.username.clone()),
                SQLiteValue::Integer(if record.enabled { 1 } else { 0 }),
                SQLiteValue::Text(record.timestamp.clone()),
                SQLiteValue::Text(record.expires.clone()),
            ],
        )?;
        Ok((record, plaintext))
    }

    pub fn session_user(&self, session: &str) -> Result<Option<UserRecord>, Error> {
        let session = session.trim();
        if session.is_empty() {
            return Ok(None);
        }
        let rows = self.sqlite.query(
            "SELECT users.username, users.email, users.api_key, users.role, users.enabled, users.reserved, users.profile_picture, users.two_factor_enabled, users.two_factor_required, users.two_factor_secret, users.timestamp, sessions.expires, sessions.enabled AS session_enabled
             FROM sessions
             JOIN users ON users.username = sessions.username
             WHERE sessions.session = ?1
             LIMIT 1",
            &[SQLiteValue::Text(hash_secret(session))],
        )?;
        let Some(row) = rows.into_iter().next() else {
            return Ok(None);
        };
        let session_enabled = row
            .get("session_enabled")
            .and_then(|value| value.as_i64())
            .map(|value| value != 0)
            .ok_or_else(|| Error("session row is missing enabled".to_string()))?;
        if !session_enabled {
            return Ok(None);
        }
        let user_enabled = row
            .get("enabled")
            .and_then(|value| value.as_i64())
            .map(|value| value != 0)
            .ok_or_else(|| Error("user row is missing enabled".to_string()))?;
        if !user_enabled {
            return Ok(None);
        }
        let expires = row
            .get("expires")
            .and_then(|value| value.as_str())
            .ok_or_else(|| Error("session row is missing expires".to_string()))?;
        let expires = chrono::DateTime::parse_from_rfc3339(expires)
            .map_err(|error| Error(format!("invalid session expiry {}: {}", expires, error)))?
            .with_timezone(&chrono::Utc);
        if chrono::Utc::now() >= expires {
            return Ok(None);
        }
        Ok(Some(user_record_from_row(row)?))
    }

    pub fn login_challenge_create(
        &self,
        username: &str,
        setup_required: bool,
        ttl_seconds: u64,
    ) -> Result<(LoginChallengeRecord, String), Error> {
        let username = normalize_username(username)?;
        let current = self
            .user_get(&username)?
            .ok_or_else(|| Error(format!("user {} does not exist", username)))?;
        if !current.enabled {
            return Err(Error(format!("user {} is disabled", username)));
        }
        let plaintext = generate_secret();
        let now = chrono::Utc::now();
        let expires = now
            .checked_add_signed(chrono::TimeDelta::seconds(ttl_seconds as i64))
            .ok_or_else(|| Error("failed to compute login challenge expiry".to_string()))?;
        let record = LoginChallengeRecord {
            id: generate_login_challenge_id(),
            username: username.to_string(),
            setup_required,
            enabled: true,
            timestamp: now.to_rfc3339(),
            expires: expires.to_rfc3339(),
        };
        self.sqlite.execute(
            "INSERT INTO login_challenges (id, challenge, username, setup_required, enabled, timestamp, expires)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            &[
                SQLiteValue::Text(record.id.clone()),
                SQLiteValue::Text(hash_secret(&plaintext)),
                SQLiteValue::Text(record.username.clone()),
                SQLiteValue::Integer(if record.setup_required { 1 } else { 0 }),
                SQLiteValue::Integer(if record.enabled { 1 } else { 0 }),
                SQLiteValue::Text(record.timestamp.clone()),
                SQLiteValue::Text(record.expires.clone()),
            ],
        )?;
        Ok((record, plaintext))
    }

    pub fn login_challenge_user(
        &self,
        challenge: &str,
    ) -> Result<Option<(UserRecord, LoginChallengeRecord)>, Error> {
        let challenge = challenge.trim();
        if challenge.is_empty() {
            return Ok(None);
        }
        let rows = self.sqlite.query(
            "SELECT users.username, users.email, users.api_key, users.role, users.enabled, users.reserved,
                    users.profile_picture, users.two_factor_enabled, users.two_factor_required, users.two_factor_secret,
                    users.timestamp,
                    login_challenges.id AS challenge_id,
                    login_challenges.setup_required,
                    login_challenges.enabled AS challenge_enabled,
                    login_challenges.timestamp AS challenge_timestamp,
                    login_challenges.expires
             FROM login_challenges
             JOIN users ON users.username = login_challenges.username
             WHERE login_challenges.challenge = ?1
             LIMIT 1",
            &[SQLiteValue::Text(hash_secret(challenge))],
        )?;
        let Some(row) = rows.into_iter().next() else {
            return Ok(None);
        };
        let enabled = row
            .get("challenge_enabled")
            .and_then(|value| value.as_i64())
            .map(|value| value != 0)
            .ok_or_else(|| Error("login challenge row is missing enabled".to_string()))?;
        if !enabled {
            return Ok(None);
        }
        let expires = row
            .get("expires")
            .and_then(|value| value.as_str())
            .ok_or_else(|| Error("login challenge row is missing expires".to_string()))?
            .to_string();
        let expiry = chrono::DateTime::parse_from_rfc3339(&expires)
            .map_err(|error| Error(error.to_string()))?
            .with_timezone(&chrono::Utc);
        if expiry < chrono::Utc::now() {
            return Ok(None);
        }
        let record = LoginChallengeRecord {
            id: row
                .get("challenge_id")
                .and_then(|value| value.as_str())
                .ok_or_else(|| Error("login challenge row is missing id".to_string()))?
                .to_string(),
            username: row
                .get("username")
                .and_then(|value| value.as_str())
                .ok_or_else(|| Error("login challenge row is missing username".to_string()))?
                .to_string(),
            setup_required: row
                .get("setup_required")
                .and_then(|value| value.as_i64())
                .map(|value| value != 0)
                .unwrap_or(false),
            enabled,
            timestamp: row
                .get("challenge_timestamp")
                .and_then(|value| value.as_str())
                .ok_or_else(|| Error("login challenge row is missing timestamp".to_string()))?
                .to_string(),
            expires,
        };
        Ok(Some((user_record_from_row(row)?, record)))
    }

    pub fn login_challenge_disable_value(&self, challenge: &str) -> Result<bool, Error> {
        let challenge = challenge.trim();
        if challenge.is_empty() {
            return Ok(false);
        }
        self.sqlite.execute(
            "UPDATE login_challenges SET enabled = 0 WHERE challenge = ?1",
            &[SQLiteValue::Text(hash_secret(challenge))],
        )?;
        Ok(true)
    }

    pub fn session_disable_value(&self, session: &str) -> Result<bool, Error> {
        let session = session.trim();
        if session.is_empty() {
            return Err(Error("session must not be empty".to_string()));
        }
        self.sqlite.execute(
            "UPDATE sessions SET enabled = 0 WHERE session = ?1",
            &[SQLiteValue::Text(hash_secret(session))],
        )?;
        let rows = self.sqlite.query(
            "SELECT enabled FROM sessions WHERE session = ?1",
            &[SQLiteValue::Text(hash_secret(session))],
        )?;
        Ok(!rows.is_empty())
    }

    pub fn session_clear(&self) -> Result<usize, Error> {
        let now = chrono::Utc::now().to_rfc3339();
        let before = self.sqlite.query(
            "SELECT id FROM sessions WHERE expires <= ?1",
            &[SQLiteValue::Text(now.clone())],
        )?;
        self.sqlite.execute(
            "DELETE FROM sessions WHERE expires <= ?1",
            &[SQLiteValue::Text(now)],
        )?;
        Ok(before.len())
    }

    pub fn captcha_create(
        &self,
        answer: &str,
        ttl_seconds: u64,
    ) -> Result<(CaptchaRecord, String), Error> {
        let answer = answer.trim().to_ascii_lowercase();
        if answer.is_empty() {
            return Err(Error("captcha answer must not be empty".to_string()));
        }
        let now = chrono::Utc::now();
        let expires = now
            .checked_add_signed(chrono::TimeDelta::seconds(ttl_seconds as i64))
            .ok_or_else(|| Error("failed to compute captcha expiry".to_string()))?;
        let record = CaptchaRecord {
            id: generate_captcha_id(),
            answer_hash: hash_secret(&answer),
            used: false,
            timestamp: now.to_rfc3339(),
            expires: expires.to_rfc3339(),
        };
        self.sqlite.execute(
            "INSERT INTO captchas (id, answer_hash, used, timestamp, expires)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &[
                SQLiteValue::Text(record.id.clone()),
                SQLiteValue::Text(record.answer_hash.clone()),
                SQLiteValue::Integer(0),
                SQLiteValue::Text(record.timestamp.clone()),
                SQLiteValue::Text(record.expires.clone()),
            ],
        )?;
        Ok((record, answer))
    }

    pub fn captcha_verify_once(&self, id: &str, answer: &str) -> Result<(), Error> {
        let id = id.trim();
        let answer = answer.trim().to_ascii_lowercase();
        if id.is_empty() || answer.is_empty() {
            return Err(Error("captcha is required".to_string()));
        }
        let rows = self.sqlite.query(
            "SELECT used, expires
             FROM captchas
             WHERE id = ?1
             LIMIT 1",
            &[SQLiteValue::Text(id.to_string())],
        )?;
        let Some(row) = rows.into_iter().next() else {
            return Err(Error("captcha challenge is invalid".to_string()));
        };
        let used = row
            .get("used")
            .and_then(|value| value.as_i64())
            .map(|value| value != 0)
            .ok_or_else(|| Error("captcha row is missing used".to_string()))?;
        if used {
            return Err(Error("captcha challenge has already been used".to_string()));
        }
        let expires = row
            .get("expires")
            .and_then(|value| value.as_str())
            .ok_or_else(|| Error("captcha row is missing expires".to_string()))?;
        let expires = chrono::DateTime::parse_from_rfc3339(expires)
            .map_err(|error| Error(format!("invalid captcha expiry {}: {}", expires, error)))?
            .with_timezone(&chrono::Utc);
        self.sqlite.execute(
            "UPDATE captchas SET used = 1 WHERE id = ?1",
            &[SQLiteValue::Text(id.to_string())],
        )?;
        if chrono::Utc::now() >= expires {
            return Err(Error("captcha challenge has expired".to_string()));
        }
        let rows = self.sqlite.query(
            "SELECT id FROM captchas WHERE id = ?1 AND answer_hash = ?2 LIMIT 1",
            &[
                SQLiteValue::Text(id.to_string()),
                SQLiteValue::Text(hash_secret(&answer)),
            ],
        )?;
        if rows.is_empty() {
            return Err(Error("captcha answer is invalid".to_string()));
        }
        Ok(())
    }

    pub fn captcha_clear_expired(&self) -> Result<usize, Error> {
        let now = chrono::Utc::now().to_rfc3339();
        let before = self.sqlite.query(
            "SELECT id FROM captchas WHERE expires <= ?1 OR used = 1",
            &[SQLiteValue::Text(now.clone())],
        )?;
        self.sqlite.execute(
            "DELETE FROM captchas WHERE expires <= ?1 OR used = 1",
            &[SQLiteValue::Text(now)],
        )?;
        Ok(before.len())
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
                username TEXT NOT NULL DEFAULT '',
                timestamp TEXT NOT NULL,
                PRIMARY KEY (tag)
            );
            CREATE TABLE IF NOT EXISTS collection_tags (
                sha256 TEXT NOT NULL,
                collection TEXT NOT NULL,
                address INTEGER NOT NULL,
                tag TEXT NOT NULL,
                username TEXT NOT NULL DEFAULT '',
                timestamp TEXT NOT NULL,
                PRIMARY KEY (sha256, collection, address, tag)
            );
            CREATE TABLE IF NOT EXISTS entity_corpora (
                sha256 TEXT NOT NULL,
                collection TEXT NOT NULL,
                architecture TEXT NOT NULL,
                address INTEGER NOT NULL,
                corpus TEXT NOT NULL,
                username TEXT NOT NULL DEFAULT '',
                timestamp TEXT NOT NULL,
                PRIMARY KEY (sha256, collection, architecture, address, corpus)
            );
            CREATE TABLE IF NOT EXISTS corpora_catalog (
                corpus TEXT NOT NULL,
                username TEXT NOT NULL DEFAULT '',
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
                collection_tag_count INTEGER NOT NULL DEFAULT 0,
                collection_tags_json TEXT NOT NULL DEFAULT '[]',
                collection_comment_count INTEGER NOT NULL DEFAULT 0,
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
            CREATE TABLE IF NOT EXISTS entity_comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sha256 TEXT NOT NULL,
                collection TEXT NOT NULL,
                address INTEGER NOT NULL,
                username TEXT NOT NULL DEFAULT '',
                comment TEXT NOT NULL,
                timestamp TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_entity_comments_lookup
                ON entity_comments (sha256, collection, address, timestamp DESC, id DESC);
            CREATE INDEX IF NOT EXISTS idx_entity_comments_timestamp
                ON entity_comments (timestamp DESC, id DESC);
            CREATE TABLE IF NOT EXISTS symbols (
                symbol TEXT NOT NULL,
                username TEXT NOT NULL DEFAULT '',
                timestamp TEXT NOT NULL,
                PRIMARY KEY (symbol)
            );
            CREATE TABLE IF NOT EXISTS roles (
                name TEXT PRIMARY KEY NOT NULL,
                timestamp TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY NOT NULL,
                email TEXT NOT NULL DEFAULT '',
                password_hash TEXT NOT NULL DEFAULT '',
                role TEXT NOT NULL,
                api_key TEXT NOT NULL,
                enabled INTEGER NOT NULL,
                reserved INTEGER NOT NULL,
                profile_picture TEXT NULL,
                two_factor_enabled INTEGER NOT NULL DEFAULT 0,
                two_factor_required INTEGER NOT NULL DEFAULT 0,
                two_factor_secret TEXT NULL,
                timestamp TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY NOT NULL,
                session TEXT NOT NULL,
                username TEXT NOT NULL,
                enabled INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                expires TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS login_challenges (
                id TEXT PRIMARY KEY NOT NULL,
                challenge TEXT NOT NULL,
                username TEXT NOT NULL,
                setup_required INTEGER NOT NULL,
                enabled INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                expires TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS recovery_codes (
                username TEXT NOT NULL,
                code_hash TEXT NOT NULL,
                enabled INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                PRIMARY KEY (username, code_hash)
            );
            CREATE TABLE IF NOT EXISTS tokens (
                id TEXT PRIMARY KEY NOT NULL,
                token TEXT NOT NULL,
                enabled INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                expires TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS captchas (
                id TEXT PRIMARY KEY NOT NULL,
                answer_hash TEXT NOT NULL,
                used INTEGER NOT NULL,
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
            CREATE INDEX IF NOT EXISTS idx_symbols_symbol ON symbols (symbol);
            CREATE INDEX IF NOT EXISTS idx_recovery_codes_username ON recovery_codes (username);
            CREATE INDEX IF NOT EXISTS idx_captchas_expires ON captchas (expires);",
        )?;
        for statement in [
            "ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE users ADD COLUMN password_hash TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE users ADD COLUMN profile_picture TEXT NULL",
            "ALTER TABLE users ADD COLUMN two_factor_enabled INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE users ADD COLUMN two_factor_required INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE users ADD COLUMN two_factor_secret TEXT NULL",
            "ALTER TABLE tags ADD COLUMN username TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE collection_tags ADD COLUMN username TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE entity_corpora ADD COLUMN username TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE corpora_catalog ADD COLUMN username TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE symbols ADD COLUMN username TEXT NOT NULL DEFAULT ''",
        ] {
            match self.sqlite.execute(statement, &[]) {
                Ok(_) => {}
                Err(error) if error.to_string().contains("duplicate column name") => {}
                Err(error) => return Err(error.into()),
            }
        }
        match self.sqlite.execute(
            "ALTER TABLE entity_metadata ADD COLUMN markov REAL NULL",
            &[],
        ) {
            Ok(_) => {}
            Err(error) if error.to_string().contains("duplicate column name") => {}
            Err(error) => return Err(error.into()),
        }
        match self.sqlite.execute(
            "ALTER TABLE entity_metadata ADD COLUMN collection_comment_count INTEGER NOT NULL DEFAULT 0",
            &[],
        ) {
            Ok(_) => {}
            Err(error) if error.to_string().contains("duplicate column name") => {}
            Err(error) => return Err(error.into()),
        }
        match self.sqlite.execute(
            "ALTER TABLE entity_metadata ADD COLUMN collection_tag_count INTEGER NOT NULL DEFAULT 0",
            &[],
        ) {
            Ok(_) => {}
            Err(error) if error.to_string().contains("duplicate column name") => {}
            Err(error) => return Err(error.into()),
        }
        match self.sqlite.execute(
            "ALTER TABLE entity_metadata ADD COLUMN collection_tags_json TEXT NOT NULL DEFAULT '[]'",
            &[],
        ) {
            Ok(_) => {}
            Err(error) if error.to_string().contains("duplicate column name") => {}
            Err(error) => return Err(error.into()),
        }
        self.cleanup_legacy_auth_state()?;
        self.ensure_reserved_auth_objects()?;
        self.ensure_default_corpora()?;
        Ok(())
    }

    fn ensure_default_corpora(&self) -> Result<(), Error> {
        for corpus in ["goodware", "malware"] {
            self.corpus_add(corpus, None, None)?;
        }
        Ok(())
    }

    fn cleanup_legacy_auth_state(&self) -> Result<(), Error> {
        self.sqlite.execute(
            "DELETE FROM sessions WHERE username IN (
                SELECT username FROM users WHERE coalesce(password_hash, '') = ''
            )",
            &[],
        )?;
        self.sqlite.execute(
            "DELETE FROM users WHERE coalesce(password_hash, '') = ''",
            &[],
        )?;
        Ok(())
    }

    fn replace_recovery_codes(
        &self,
        username: &str,
        codes: &[String],
        timestamp: &str,
    ) -> Result<(), Error> {
        self.sqlite.execute(
            "DELETE FROM recovery_codes WHERE username = ?1",
            &[SQLiteValue::Text(username.to_string())],
        )?;
        for code in codes
            .iter()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        {
            self.sqlite.execute(
                "INSERT INTO recovery_codes (username, code_hash, enabled, timestamp)
                 VALUES (?1, ?2, ?3, ?4)",
                &[
                    SQLiteValue::Text(username.to_string()),
                    SQLiteValue::Text(hash_secret(code)),
                    SQLiteValue::Integer(1),
                    SQLiteValue::Text(timestamp.to_string()),
                ],
            )?;
        }
        Ok(())
    }

    fn consume_recovery_code(
        &self,
        username: &str,
        recovery_code: &str,
        timestamp: Option<&str>,
    ) -> Result<String, Error> {
        let recovery_code = recovery_code.trim();
        if recovery_code.is_empty() {
            return Err(Error("recovery code must not be empty".to_string()));
        }
        let code_hash = hash_secret(recovery_code);
        let rows = self.sqlite.query(
            "SELECT enabled FROM recovery_codes
             WHERE username = ?1 AND code_hash = ?2
             LIMIT 1",
            &[
                SQLiteValue::Text(username.to_string()),
                SQLiteValue::Text(code_hash.clone()),
            ],
        )?;
        let Some(row) = rows.into_iter().next() else {
            return Err(Error("invalid recovery code".to_string()));
        };
        let enabled = row
            .get("enabled")
            .and_then(|value| value.as_i64())
            .map(|value| value != 0)
            .ok_or_else(|| Error("recovery code row is missing enabled".to_string()))?;
        if !enabled {
            return Err(Error("recovery code has already been used".to_string()));
        }
        let when = timestamp
            .map(ToString::to_string)
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
        self.sqlite.execute(
            "UPDATE recovery_codes SET enabled = 0, timestamp = ?1 WHERE username = ?2 AND code_hash = ?3",
            &[
                SQLiteValue::Text(when.clone()),
                SQLiteValue::Text(username.to_string()),
                SQLiteValue::Text(code_hash),
            ],
        )?;
        Ok(when)
    }

    fn ensure_reserved_auth_objects(&self) -> Result<(), Error> {
        let now = chrono::Utc::now().to_rfc3339();
        for role in ["admin", "user"] {
            if self.role_get(role)?.is_none() {
                self.role_create(role, Some(&now))?;
            }
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
        if self.user_get(&username)?.is_some() {
            return Err(Error(format!("user {} already exists", username)));
        }
        let record = UserRecord {
            username: username.to_string(),
            api_key: api_key.to_string(),
            role: role.to_string(),
            enabled: true,
            reserved,
            profile_picture: None,
            two_factor_enabled: false,
            two_factor_required: false,
            timestamp: timestamp
                .map(ToString::to_string)
                .unwrap_or_else(|| chrono::Utc::now().to_rfc3339()),
        };
        self.sqlite.execute(
            "INSERT INTO users (username, email, password_hash, role, api_key, enabled, reserved, profile_picture, two_factor_enabled, two_factor_required, two_factor_secret, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            &[
                SQLiteValue::Text(record.username.clone()),
                SQLiteValue::Text(String::new()),
                SQLiteValue::Text(String::new()),
                SQLiteValue::Text(record.role.clone()),
                SQLiteValue::Text(record.api_key.clone()),
                SQLiteValue::Integer(if record.enabled { 1 } else { 0 }),
                SQLiteValue::Integer(if record.reserved { 1 } else { 0 }),
                SQLiteValue::Null,
                SQLiteValue::Integer(if record.two_factor_enabled { 1 } else { 0 }),
                SQLiteValue::Integer(if record.two_factor_required { 1 } else { 0 }),
                SQLiteValue::Null,
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

fn generate_password_secret() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    crate::hex::encode(&bytes)
}

fn generate_api_key() -> String {
    generate_secret()
}

fn generate_recovery_code() -> String {
    let mut bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut bytes);
    crate::hex::encode(&bytes)
}

fn generate_recovery_codes() -> Vec<String> {
    (0..8).map(|_| generate_recovery_code()).collect()
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

fn generate_session_id() -> String {
    let mut bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!(
        "sess_{:x}_{}",
        chrono::Utc::now().timestamp_micros(),
        crate::hex::encode(&bytes)
    )
}

fn generate_login_challenge_id() -> String {
    let mut bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!(
        "login_{:x}_{}",
        chrono::Utc::now().timestamp_micros(),
        crate::hex::encode(&bytes)
    )
}

fn generate_captcha_id() -> String {
    let mut bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!(
        "cap_{:x}_{}",
        chrono::Utc::now().timestamp_micros(),
        crate::hex::encode(&bytes)
    )
}

fn hash_secret(value: &str) -> String {
    crate::hex::encode(digest(&SHA256, value.as_bytes()).as_ref())
}

fn hash_password(password: &str) -> Result<String, Error> {
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let iterations = NonZeroU32::new(120_000)
        .ok_or_else(|| Error("invalid password iteration count".to_string()))?;
    let mut output = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        &salt,
        password.as_bytes(),
        &mut output,
    );
    Ok(format!(
        "pbkdf2_sha256${}${}${}",
        iterations.get(),
        crate::hex::encode(&salt),
        crate::hex::encode(&output)
    ))
}

fn verify_password(encoded: &str, password: &str) -> Result<bool, Error> {
    let mut parts = encoded.split('$');
    let Some(algorithm) = parts.next() else {
        return Ok(false);
    };
    if algorithm != "pbkdf2_sha256" {
        return Ok(false);
    }
    let iterations = parts
        .next()
        .ok_or_else(|| Error("password hash is missing iterations".to_string()))?
        .parse::<u32>()
        .map_err(|error| Error(format!("invalid password hash iterations: {}", error)))?;
    let salt = crate::hex::decode(
        parts
            .next()
            .ok_or_else(|| Error("password hash is missing salt".to_string()))?,
    )
    .map_err(|error| Error(format!("invalid password hash salt: {}", error)))?;
    let hash = crate::hex::decode(
        parts
            .next()
            .ok_or_else(|| Error("password hash is missing digest".to_string()))?,
    )
    .map_err(|error| Error(format!("invalid password hash digest: {}", error)))?;
    let iterations = NonZeroU32::new(iterations)
        .ok_or_else(|| Error("password hash has invalid iteration count".to_string()))?;
    Ok(pbkdf2::verify(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        &salt,
        password.as_bytes(),
        &hash,
    )
    .is_ok())
}

fn normalize_username(value: &str) -> Result<String, Error> {
    let value = value.trim();
    if value.is_empty() {
        return Err(Error("username must not be empty".to_string()));
    }
    if value.len() > 15 {
        return Err(Error("username must be at most 15 characters".to_string()));
    }
    let normalized = value.to_ascii_lowercase();
    if !normalized
        .chars()
        .all(|character| character.is_ascii_lowercase() || character.is_ascii_digit())
    {
        return Err(Error(
            "username must contain only lowercase letters and digits".to_string(),
        ));
    }
    Ok(normalized)
}

fn normalize_role_name(value: &str) -> Result<&str, Error> {
    let value = value.trim();
    if value.is_empty() {
        return Err(Error("role must not be empty".to_string()));
    }
    Ok(value)
}

fn normalize_password(value: &str) -> Result<&str, Error> {
    let value = value.trim();
    if value.len() < 12 {
        return Err(Error("password must be at least 12 characters".to_string()));
    }
    if value.len() > 32 {
        return Err(Error("password must be at most 32 characters".to_string()));
    }
    Ok(value)
}

pub(crate) fn normalize_metadata_name(kind: &str, value: &str) -> Result<String, Error> {
    let value = value.trim();
    if value.is_empty() {
        return Err(Error(format!("{} must not be empty", kind)));
    }
    if value.chars().any(char::is_whitespace) {
        return Err(Error(format!("{} must not contain whitespace", kind)));
    }
    Ok(value.to_string())
}

fn is_reserved_role(value: &str) -> bool {
    matches!(value, "admin" | "user")
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
        api_key: row
            .get("api_key")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
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
        profile_picture: row
            .get("profile_picture")
            .and_then(|value| value.as_str())
            .map(ToString::to_string),
        two_factor_enabled: row
            .get("two_factor_enabled")
            .and_then(|value| value.as_i64())
            .map(|value| value != 0)
            .unwrap_or(false),
        two_factor_required: row
            .get("two_factor_required")
            .and_then(|value| value.as_i64())
            .map(|value| value != 0)
            .unwrap_or(false),
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
    let collection_tags = row
        .get("collection_tags_json")
        .cloned()
        .map(serde_json::from_value::<Vec<String>>)
        .transpose()
        .or_else(|_| {
            row.get("collection_tags_json")
                .and_then(|value| value.as_str())
                .map(|value| serde_json::from_str::<Vec<String>>(value))
                .transpose()
        })
        .map_err(|error| Error(error.to_string()))?
        .unwrap_or_default();
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
        collection_tag_count: row
            .get("collection_tag_count")
            .and_then(|value| value.as_u64())
            .unwrap_or(0),
        collection_tags,
        collection_comment_count: row
            .get("collection_comment_count")
            .and_then(|value| value.as_u64())
            .unwrap_or(0),
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

        db.tag_add("triage", Some("2026-04-01T00:00:03Z"), Some("admin"))
            .expect("add catalog tag");
        let tag_catalog = db.tag_search("tri", 10).expect("search tag catalog");
        assert_eq!(tag_catalog.items.len(), 1);
        assert_eq!(tag_catalog.items[0].tag, "triage");
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
            username: "admin".to_string(),
            timestamp: "2026-04-02T00:00:00Z".to_string(),
        })
        .expect("add first collection tag");
        db.collection_tag_add(&CollectionTagRecord {
            sha256: sha256.to_string(),
            collection: Collection::Block,
            address: 0x401020,
            tag: "dispatcher".to_string(),
            username: "admin".to_string(),
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
            "admin",
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

        assert_eq!(db.admin_count().expect("admin count"), 0);

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

        let (user, api_key, recovery_codes) = db
            .user_create_account(
                "researcher1",
                "supersecret123",
                "analyst",
                false,
                false,
                Some("2026-04-03T10:00:01Z"),
            )
            .expect("create user");
        assert_eq!(user.username, "researcher1");
        assert_eq!(user.role, "analyst");
        assert!(user.enabled);
        assert!(!user.reserved);
        assert_eq!(recovery_codes.len(), 8);
        assert!(db.auth_check(&api_key).expect("auth check"));
        assert_eq!(
            db.auth_user(&api_key)
                .expect("auth user")
                .expect("user exists")
                .username,
            "researcher1"
        );
        assert!(
            db.user_authenticate("researcher1", "supersecret123")
                .expect("authenticate by username")
                .is_some()
        );
        let reset_password = db
            .user_reset("researcher1", Some("2026-04-03T10:00:02Z"))
            .expect("reset user");
        assert_ne!(reset_password, "supersecret123");
        assert!(
            db.user_authenticate("researcher1", "supersecret123")
                .expect("old password invalid")
                .is_none()
        );
        assert!(
            db.user_authenticate("researcher1", &reset_password)
                .expect("new password valid")
                .is_some()
        );

        let recovery_reset_codes = db
            .user_regenerate_recovery_codes("researcher1", Some("2026-04-03T10:00:02Z"))
            .expect("regenerate recovery codes");
        let recovery_reset_password = "anothersecret123";
        db.user_reset_with_recovery_code(
            "researcher1",
            &recovery_reset_codes[0],
            recovery_reset_password,
            Some("2026-04-03T10:00:02Z"),
        )
        .expect("reset with recovery code");
        assert!(
            db.user_authenticate("researcher1", recovery_reset_password)
                .expect("recovery password valid")
                .is_some()
        );

        let regenerated_key = db
            .user_regenerate_key("researcher1", Some("2026-04-03T10:00:03Z"))
            .expect("regenerate key");
        assert_ne!(regenerated_key, api_key);
        assert!(!db.auth_check(&api_key).expect("old key invalid"));
        assert!(db.auth_check(&regenerated_key).expect("new key valid"));

        assert!(db.user_disable("researcher1").expect("disable user"));
        assert!(
            !db.auth_check(&regenerated_key)
                .expect("disabled user invalid")
        );

        assert!(db.user_enable("researcher1").expect("enable user"));
        assert!(
            db.auth_check(&regenerated_key)
                .expect("re-enabled user valid")
        );

        let users = db.user_search("research", 1, 10).expect("search users");
        assert_eq!(users.items.len(), 1);
        assert_eq!(users.items[0].username, "researcher1");

        assert!(db.role_delete("analyst").is_err());
    }

    #[test]
    fn local_db_normalizes_and_limits_usernames() {
        let root = tempfile::tempdir().expect("tempdir");
        let mut config = Config::default();
        config.databases.local.path = root.path().join("local.db").display().to_string();
        let db = LocalDB::new(&config).expect("create local db");

        let (user, _, _) = db
            .user_create_account(
                "MixedCaseUser",
                "supersecret123",
                "user",
                false,
                false,
                None,
            )
            .expect("create normalized user");
        assert_eq!(user.username, "mixedcaseuser");
        assert!(db.user_get("MIXEDCASEUSER").expect("lookup").is_some());

        let error = db
            .user_create_account(
                "thisusernameistoolong",
                "supersecret123",
                "user",
                false,
                false,
                None,
            )
            .expect_err("reject long username");
        assert!(error.to_string().contains("at most 15 characters"));

        let error = db
            .user_create_account("bad_user!", "supersecret123", "user", false, false, None)
            .expect_err("reject non alnum username");
        assert!(
            error
                .to_string()
                .contains("only lowercase letters and digits")
        );

        let error = db
            .user_create_account("shortname", "shortpass", "user", false, false, None)
            .expect_err("reject short password");
        assert!(error.to_string().contains("at least 12 characters"));

        let error = db
            .user_create_account(
                "longpassuser",
                "abcdefghijklmnopqrstuvwxyz1234567",
                "user",
                false,
                false,
                None,
            )
            .expect_err("reject long password");
        assert!(error.to_string().contains("at most 32 characters"));
    }

    #[test]
    fn local_db_seeds_default_corpora() {
        let root = tempfile::tempdir().expect("tempdir");
        let mut config = Config::default();
        config.databases.local.path = root.path().join("local.db").display().to_string();
        let db = LocalDB::new(&config).expect("create local db");

        let corpora = db.corpus_search("", 16).expect("search corpora");
        assert!(corpora.iter().any(|corpus| corpus == "goodware"));
        assert!(corpora.iter().any(|corpus| corpus == "malware"));
    }

    #[test]
    fn local_db_rejects_metadata_names_with_whitespace() {
        let root = tempfile::tempdir().expect("tempdir");
        let mut config = Config::default();
        config.databases.local.path = root.path().join("local.db").display().to_string();
        let db = LocalDB::new(&config).expect("create local db");

        let corpus_error = db
            .corpus_add("bad corpus", None, None)
            .expect_err("corpus with whitespace should fail");
        assert!(
            corpus_error
                .to_string()
                .contains("must not contain whitespace")
        );

        let tag_error = db
            .tag_add("bad tag", None, None)
            .expect_err("tag with whitespace should fail");
        assert!(
            tag_error
                .to_string()
                .contains("must not contain whitespace")
        );

        let symbol_error = db
            .symbol_add("bad symbol", None, None)
            .expect_err("symbol with whitespace should fail");
        assert!(
            symbol_error
                .to_string()
                .contains("must not contain whitespace")
        );
    }

    #[test]
    fn local_db_disabling_user_invalidates_sessions_and_preserves_enabled_admin() {
        let root = tempfile::tempdir().expect("tempdir");
        let mut config = Config::default();
        config.databases.local.path = root.path().join("local.db").display().to_string();
        let db = LocalDB::new(&config).expect("create local db");

        let (admin1, _, _) = db
            .user_create_account("adminone", "supersecret123", "admin", false, false, None)
            .expect("create first admin");
        let (_session, session_value) = db
            .session_create(&admin1.username, 3600)
            .expect("create session");
        assert!(
            db.session_user(&session_value)
                .expect("resolve active session")
                .is_some()
        );

        let error = db
            .user_disable(&admin1.username)
            .expect_err("cannot disable last enabled admin");
        assert!(error.to_string().contains("last enabled admin"));

        let (_admin2, _, _) = db
            .user_create_account("admintwo", "supersecret123", "admin", false, false, None)
            .expect("create second admin");
        assert!(
            db.user_disable(&admin1.username)
                .expect("disable first admin")
        );
        assert!(
            db.session_user(&session_value)
                .expect("disabled session resolves")
                .is_none()
        );
        assert!(
            db.user_authenticate(&admin1.username, "supersecret123")
                .expect("disabled admin authenticate")
                .is_none()
        );
        assert!(
            db.user_enable(&admin1.username)
                .expect("re-enable first admin")
        );
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
