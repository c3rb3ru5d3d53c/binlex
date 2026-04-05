use crate::Config;
use crate::databases::{LanceDB, LocalDB};
use crate::storage::localstore;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

mod indexing;
mod lancedb;
mod localdb;
mod mutations;
mod query;
mod search;
mod storage;
mod support;
mod types;

pub use self::query::{CompareResult, QueryResult};
use self::types::PendingBatch;
pub use self::types::{
    CollectionCommentRecord, CollectionCommentSearchPage, CollectionTagRecord,
    CollectionTagSearchPage, CommentRecord, CommentSearchPage, Error, SampleStatusRecord,
    SearchResult, TagRecord, TagSearchPage,
};

#[derive(Clone)]
pub struct LocalIndex {
    config: Config,
    store: localstore::LocalStore,
    lancedb: LanceDB,
    localdb: Arc<LocalDB>,
    pending: Arc<Mutex<PendingBatch>>,
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
        let root = support::resolve_root(directory, &config)?;
        let mut config = config;
        if let Some(dimensions) = dimensions {
            config.index.local.dimensions = Some(dimensions);
        }
        let store = localstore::LocalStore::with_root(root.join("store"))
            .map_err(|error| Error::LocalStore(error.to_string()))?;
        let lancedb = LanceDB::new(root.join("lancedb"))
            .map_err(|error| Error::LanceDb(error.to_string()))?;
        let mut localdb_config = config.clone();
        localdb_config.databases.local.path = root.join("local.db").display().to_string();
        let localdb = Arc::new(
            LocalDB::new(&localdb_config).map_err(|error| Error::LocalDb(error.to_string()))?,
        );
        let index = Self {
            config,
            store,
            lancedb,
            localdb,
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
}

#[cfg(test)]
mod tests;
