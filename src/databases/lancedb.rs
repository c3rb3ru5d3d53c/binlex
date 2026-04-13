use arrow_array::{RecordBatch, RecordBatchIterator};
use arrow_schema::{DataType, Schema};
use futures::TryStreamExt;
use lancedb::Connection;
use lancedb::query::{ExecutableQuery, QueryBase};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::runtime::{Builder, Runtime};

#[derive(Clone)]
pub struct LanceDB {
    root: PathBuf,
    runtime: Arc<Runtime>,
}

#[derive(Debug)]
pub enum Error {
    InvalidConfiguration(&'static str),
    Io(String),
    Lance(String),
    Arrow(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(message) => {
                write!(f, "lancedb configuration error: {}", message)
            }
            Self::Io(message) => write!(f, "lancedb io error: {}", message),
            Self::Lance(message) => write!(f, "lancedb error: {}", message),
            Self::Arrow(message) => write!(f, "lancedb arrow error: {}", message),
        }
    }
}

impl std::error::Error for Error {}

impl LanceDB {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, Error> {
        let root = root.into();
        if root.as_os_str().is_empty() {
            return Err(Error::InvalidConfiguration("root must not be empty"));
        }
        std::fs::create_dir_all(&root).map_err(|error| Error::Io(error.to_string()))?;
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| Error::Io(error.to_string()))?;
        Ok(Self {
            root,
            runtime: Arc::new(runtime),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn table_dimensions_by_name(&self, table_name: &str) -> Result<Option<usize>, Error> {
        let connection = self.connection()?;
        let table = match self
            .runtime
            .block_on(connection.open_table(table_name).execute())
        {
            Ok(table) => table,
            Err(_) => return Ok(None),
        };
        let schema = self
            .runtime
            .block_on(table.schema())
            .map_err(|error| Error::Lance(error.to_string()))?;
        vector_dimensions_from_schema(schema.as_ref()).map(Some)
    }

    pub fn table_names(&self) -> Result<Vec<String>, Error> {
        let connection = self.connection()?;
        self.runtime
            .block_on(connection.table_names().execute())
            .map_err(|error| Error::Lance(error.to_string()))
    }

    pub fn upsert_batches(
        &self,
        table_name: &str,
        schema: Arc<Schema>,
        merge_keys: &[&str],
        batches: Vec<RecordBatch>,
    ) -> Result<(), Error> {
        if batches.is_empty() {
            return Ok(());
        }
        if merge_keys.is_empty() {
            return Err(Error::InvalidConfiguration("merge_keys must not be empty"));
        }
        let connection = self.connection()?;
        self.ensure_table(&connection, table_name, schema)?;
        let table = self
            .runtime
            .block_on(connection.open_table(table_name).execute())
            .map_err(|error| Error::Lance(error.to_string()))?;
        let reader = batch_reader_for_batches(batches);
        let mut merge_insert = table.merge_insert(merge_keys);
        merge_insert
            .when_matched_update_all(None)
            .when_not_matched_insert_all();
        self.runtime
            .block_on(merge_insert.execute(reader))
            .map_err(|error| Error::Lance(error.to_string()))?;
        Ok(())
    }

    pub fn delete_where(&self, table_name: &str, predicate: &str) -> Result<(), Error> {
        if predicate.trim().is_empty() {
            return Ok(());
        }
        let connection = self.connection()?;
        let table = match self
            .runtime
            .block_on(connection.open_table(table_name).execute())
        {
            Ok(table) => table,
            Err(_) => return Ok(()),
        };
        self.runtime
            .block_on(table.delete(predicate))
            .map_err(|error| Error::Lance(error.to_string()))?;
        Ok(())
    }

    pub fn vector_search(
        &self,
        table_name: &str,
        vector: &[f32],
        limit: usize,
    ) -> Result<Vec<RecordBatch>, Error> {
        let connection = self.connection()?;
        let table = self
            .runtime
            .block_on(connection.open_table(table_name).execute())
            .map_err(|error| Error::Lance(error.to_string()))?;
        let query = table
            .vector_search(vector)
            .map_err(|error| Error::Lance(error.to_string()))?
            .limit(limit);
        let mut stream = self
            .runtime
            .block_on(query.execute())
            .map_err(|error| Error::Lance(error.to_string()))?;
        let mut batches = Vec::new();
        while let Some(batch) = self
            .runtime
            .block_on(stream.try_next())
            .map_err(|error| Error::Lance(error.to_string()))?
        {
            batches.push(batch);
        }
        Ok(batches)
    }

    fn connection(&self) -> Result<Connection, Error> {
        self.runtime
            .block_on(lancedb::connect(self.root.to_string_lossy().as_ref()).execute())
            .map_err(|error| Error::Lance(error.to_string()))
    }

    fn ensure_table(
        &self,
        connection: &Connection,
        table_name: &str,
        schema: Arc<Schema>,
    ) -> Result<(), Error> {
        if self
            .runtime
            .block_on(connection.open_table(table_name).execute())
            .is_ok()
        {
            return Ok(());
        }
        self.runtime
            .block_on(connection.create_empty_table(table_name, schema).execute())
            .map_err(|error| Error::Lance(error.to_string()))?;
        Ok(())
    }
}

fn vector_dimensions_from_schema(schema: &Schema) -> Result<usize, Error> {
    let field = schema
        .field_with_name("vector")
        .map_err(|error| Error::Arrow(error.to_string()))?;
    match field.data_type() {
        DataType::FixedSizeList(_, dims) => {
            usize::try_from(*dims).map_err(|error| Error::Arrow(error.to_string()))
        }
        other => Err(Error::Arrow(format!(
            "vector column type mismatch: expected fixed-size list, got {}",
            other
        ))),
    }
}

fn batch_reader_for_batches(
    batches: Vec<RecordBatch>,
) -> Box<dyn arrow_array::RecordBatchReader + Send> {
    let schema = batches[0].schema();
    Box::new(RecordBatchIterator::new(
        batches.into_iter().map(Ok),
        schema,
    ))
}
