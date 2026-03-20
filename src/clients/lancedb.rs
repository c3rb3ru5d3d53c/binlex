use crate::clients::local_store::Collection;
use arrow_array::{FixedSizeListArray, Float32Array, RecordBatch, StringArray};
use arrow_schema::{DataType, Field, Schema};
use futures::TryStreamExt;
use lancedb::Connection;
use lancedb::query::{ExecutableQuery, QueryBase};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::runtime::{Builder, Runtime};

#[derive(Clone)]
pub struct Client {
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

#[derive(Clone, Debug)]
pub struct Row {
    pub object_id: String,
    pub occurrences_json: String,
    pub vector: Vec<f32>,
}

impl Client {
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

    pub fn upsert(
        &self,
        corpus: &str,
        collection: Collection,
        architecture: &str,
        object_id: &str,
        vector: &[f32],
        occurrences_json: &str,
    ) -> Result<(), Error> {
        let connection = self.connection()?;
        let table_name = table_name(corpus, collection, architecture);
        let dims = i32::try_from(vector.len()).map_err(|error| Error::Arrow(error.to_string()))?;
        self.ensure_table(&connection, &table_name, dims)?;
        let table = self
            .runtime
            .block_on(connection.open_table(&table_name).execute())
            .map_err(|error| Error::Lance(error.to_string()))?;
        let escaped = object_id.replace('\'', "''");
        self.runtime
            .block_on(table.delete(&format!("object_id = '{}'", escaped)))
            .map_err(|error| Error::Lance(error.to_string()))?;
        let batch = record_batch_for_row(object_id, vector, occurrences_json)?;
        self.runtime
            .block_on(table.add(vec![batch]).execute())
            .map_err(|error| Error::Lance(error.to_string()))?;
        Ok(())
    }

    pub fn search(
        &self,
        corpus: &str,
        collection: Collection,
        architecture: &str,
        vector: &[f32],
        limit: usize,
    ) -> Result<Vec<Row>, Error> {
        let connection = self.connection()?;
        let table_name = table_name(corpus, collection, architecture);
        let table = self
            .runtime
            .block_on(connection.open_table(&table_name).execute())
            .map_err(|error| Error::Lance(error.to_string()))?;
        let query = table
            .vector_search(vector)
            .map_err(|error| Error::Lance(error.to_string()))?
            .limit(limit);
        let mut stream = self
            .runtime
            .block_on(query.execute())
            .map_err(|error| Error::Lance(error.to_string()))?;
        let mut rows = Vec::new();
        while let Some(batch) = self
            .runtime
            .block_on(stream.try_next())
            .map_err(|error| Error::Lance(error.to_string()))?
        {
            rows.extend(rows_from_batch(&batch)?);
        }
        Ok(rows)
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
        dims: i32,
    ) -> Result<(), Error> {
        if self
            .runtime
            .block_on(connection.open_table(table_name).execute())
            .is_ok()
        {
            return Ok(());
        }
        let schema = schema_for_table(dims);
        self.runtime
            .block_on(connection.create_empty_table(table_name, schema).execute())
            .map_err(|error| Error::Lance(error.to_string()))?;
        Ok(())
    }
}

fn schema_for_table(dims: i32) -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("object_id", DataType::Utf8, false),
        Field::new("occurrences", DataType::Utf8, false),
        Field::new(
            "vector",
            DataType::FixedSizeList(Arc::new(Field::new("item", DataType::Float32, true)), dims),
            true,
        ),
    ]))
}

fn record_batch_for_row(
    object_id: &str,
    vector: &[f32],
    occurrences_json: &str,
) -> Result<RecordBatch, Error> {
    let dims = i32::try_from(vector.len()).map_err(|error| Error::Arrow(error.to_string()))?;
    let schema = schema_for_table(dims);
    RecordBatch::try_new(
        schema,
        vec![
            Arc::new(StringArray::from(vec![object_id])),
            Arc::new(StringArray::from(vec![occurrences_json])),
            Arc::new(FixedSizeListArray::from_iter_primitive::<
                arrow_array::types::Float32Type,
                _,
                _,
            >(
                vec![Some(vector.iter().copied().map(Some).collect::<Vec<_>>())],
                dims,
            )),
        ],
    )
    .map_err(|error| Error::Arrow(error.to_string()))
}

fn rows_from_batch(batch: &RecordBatch) -> Result<Vec<Row>, Error> {
    let object_ids = batch
        .column_by_name("object_id")
        .ok_or_else(|| Error::Arrow("missing object_id column".to_string()))?
        .as_any()
        .downcast_ref::<StringArray>()
        .ok_or_else(|| Error::Arrow("object_id column type mismatch".to_string()))?;
    let occurrences = batch
        .column_by_name("occurrences")
        .ok_or_else(|| Error::Arrow("missing occurrences column".to_string()))?
        .as_any()
        .downcast_ref::<StringArray>()
        .ok_or_else(|| Error::Arrow("occurrences column type mismatch".to_string()))?;
    let vectors = batch
        .column_by_name("vector")
        .ok_or_else(|| Error::Arrow("missing vector column".to_string()))?
        .as_any()
        .downcast_ref::<FixedSizeListArray>()
        .ok_or_else(|| Error::Arrow("vector column type mismatch".to_string()))?;
    let values = vectors
        .values()
        .as_any()
        .downcast_ref::<Float32Array>()
        .ok_or_else(|| Error::Arrow("vector values type mismatch".to_string()))?;

    let width =
        usize::try_from(vectors.value_length()).map_err(|error| Error::Arrow(error.to_string()))?;
    let mut rows = Vec::with_capacity(batch.num_rows());
    for index in 0..batch.num_rows() {
        let start = index * width;
        let mut vector = Vec::with_capacity(width);
        for offset in 0..width {
            vector.push(values.value(start + offset));
        }
        rows.push(Row {
            object_id: object_ids.value(index).to_string(),
            occurrences_json: occurrences.value(index).to_string(),
            vector,
        });
    }
    Ok(rows)
}

fn table_name(corpus: &str, collection: Collection, architecture: &str) -> String {
    format!("{}__{}__{}", corpus, collection.as_str(), architecture)
}
