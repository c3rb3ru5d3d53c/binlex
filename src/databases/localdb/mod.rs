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
    Stored,
}

impl SampleStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Processing => "processing",
            Self::Complete => "complete",
            Self::Failed => "failed",
            Self::Canceled => "canceled",
            Self::Stored => "stored",
        }
    }

    fn parse(value: &str) -> Result<Self, Error> {
        match value.trim().to_ascii_lowercase().as_str() {
            "pending" => Ok(Self::Pending),
            "processing" => Ok(Self::Processing),
            "complete" => Ok(Self::Complete),
            "failed" => Ok(Self::Failed),
            "canceled" => Ok(Self::Canceled),
            "stored" => Ok(Self::Stored),
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
pub struct EntitySymbolRecord {
    pub sha256: String,
    pub collection: Collection,
    pub architecture: String,
    pub address: u64,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectRecord {
    pub project_sha256: String,
    pub tool: String,
    pub original_filename: String,
    pub storage_key: String,
    pub size_bytes: u64,
    pub content_type: String,
    pub container_format: String,
    pub visibility: String,
    pub uploaded_by: String,
    pub uploaded_timestamp: String,
    pub updated_timestamp: String,
    pub is_deleted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectAssignmentRecord {
    pub assignment_sha256: String,
    pub project_sha256: String,
    pub sample_sha256: String,
    pub sample_state: String,
    pub assigned_by: String,
    pub assigned_timestamp: String,
    pub updated_timestamp: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectSearchParams {
    pub sample_sha256: String,
    pub username: Option<String>,
    pub tool: Option<String>,
    pub project_sha256: Option<String>,
    pub page: usize,
    pub page_size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SampleSha256Record {
    pub sha256: String,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CountedPage<T> {
    pub items: Vec<T>,
    pub page: usize,
    pub page_size: usize,
    pub total_results: usize,
    pub has_next: bool,
}

pub struct LocalDB {
    sqlite: SQLite,
}

mod auth;
mod comments;
mod core;
mod corpus;
mod projects;
mod tags;

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

fn symbol_type_matches_collection(value: &str, collection: Collection) -> bool {
    matches!(
        (collection, value),
        (Collection::Instruction, "instruction")
            | (Collection::Block, "block")
            | (Collection::Function, "function")
    )
}

fn entity_symbol_records_from_attributes(
    sha256: &str,
    collection: Collection,
    architecture: &str,
    address: u64,
    attributes: &[serde_json::Value],
) -> Vec<EntitySymbolRecord> {
    let mut items = attributes
        .iter()
        .filter_map(|attribute| {
            let object = attribute.as_object()?;
            if object.get("type")?.as_str()? != "symbol" {
                return None;
            }
            let symbol = object.get("name")?.as_str()?.trim();
            if symbol.is_empty() {
                return None;
            }
            let symbol_type = object.get("symbol_type")?.as_str()?;
            if !symbol_type_matches_collection(symbol_type, collection) {
                return None;
            }
            let symbol_address = object.get("address")?.as_u64()?;
            if symbol_address != address {
                return None;
            }
            Some(EntitySymbolRecord {
                sha256: sha256.to_string(),
                collection,
                architecture: architecture.to_string(),
                address,
                symbol: symbol.to_string(),
                username: object
                    .get("username")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                timestamp: object
                    .get("timestamp")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            })
        })
        .collect::<Vec<_>>();
    items.sort_by(|lhs, rhs| lhs.symbol.cmp(&rhs.symbol));
    items.dedup_by(|lhs, rhs| lhs.symbol == rhs.symbol);
    items
}

fn parse_collection(value: &str) -> Result<Collection, Error> {
    match value.trim().to_ascii_lowercase().as_str() {
        "instructions" => Ok(Collection::Instruction),
        "blocks" => Ok(Collection::Block),
        "functions" => Ok(Collection::Function),
        _ => Err(Error(format!("invalid collection {}", value))),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CollectionCommentRecord, CollectionTagRecord, LocalDB, RoleRecord, SampleCommentRecord,
        SampleStatus, SampleStatusRecord,
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
