use crate::index::Collection;
use arrow_array::{
    Array, FixedSizeListArray, Float32Array, RecordBatch, RecordBatchIterator, StringArray,
    UInt64Array,
};
use arrow_schema::{DataType, Field, Schema};
use futures::TryStreamExt;
use lancedb::Connection;
use lancedb::query::{ExecutableQuery, QueryBase};
use std::collections::BTreeMap;
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

#[derive(Clone, Debug)]
pub struct Row {
    pub object_id: String,
    pub sha256: Option<String>,
    pub address: Option<u64>,
    pub occurrences_json: String,
    pub vector: Vec<f32>,
}

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

    pub fn table_dimensions(
        &self,
        collection: Collection,
        architecture: &str,
    ) -> Result<Option<usize>, Error> {
        self.table_dimensions_by_name(&table_name(collection, architecture))
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

    pub fn upsert(
        &self,
        entity: Collection,
        architecture: &str,
        object_id: &str,
        sha256: Option<&str>,
        address: Option<u64>,
        vector: &[f32],
        occurrences_json: &str,
    ) -> Result<(), Error> {
        let connection = self.connection()?;
        let table_name = table_name(entity, architecture);
        let dims = i32::try_from(vector.len()).map_err(|error| Error::Arrow(error.to_string()))?;
        self.ensure_table(&connection, &table_name, dims)?;
        let table = self
            .runtime
            .block_on(connection.open_table(&table_name).execute())
            .map_err(|error| Error::Lance(error.to_string()))?;
        let batch = record_batch_for_row(object_id, sha256, address, vector, occurrences_json)?;
        let reader = batch_reader_for_batches(vec![batch]);
        let mut merge_insert = table.merge_insert(&["object_id"]);
        merge_insert
            .when_matched_update_all(None)
            .when_not_matched_insert_all();
        self.runtime
            .block_on(merge_insert.execute(reader))
            .map_err(|error| Error::Lance(error.to_string()))?;
        Ok(())
    }

    pub fn upsert_rows(
        &self,
        entity: Collection,
        architecture: &str,
        rows: &[Row],
    ) -> Result<(), Error> {
        if rows.is_empty() {
            return Ok(());
        }
        let connection = self.connection()?;
        let table_name = table_name(entity, architecture);
        let dims =
            i32::try_from(rows[0].vector.len()).map_err(|error| Error::Arrow(error.to_string()))?;
        self.ensure_table(&connection, &table_name, dims)?;
        let table = self
            .runtime
            .block_on(connection.open_table(&table_name).execute())
            .map_err(|error| Error::Lance(error.to_string()))?;
        for chunk in dedupe_input_rows(rows).chunks(UPSERT_ROWS_CHUNK_SIZE) {
            let batch = record_batch_for_rows(chunk)?;
            let reader = batch_reader_for_batches(vec![batch]);
            let mut merge_insert = table.merge_insert(&["object_id"]);
            merge_insert
                .when_matched_update_all(None)
                .when_not_matched_insert_all();
            self.runtime
                .block_on(merge_insert.execute(reader))
                .map_err(|error| Error::Lance(error.to_string()))?;
        }
        Ok(())
    }

    pub fn delete_objects(
        &self,
        entity: Collection,
        architecture: &str,
        object_ids: &[String],
    ) -> Result<(), Error> {
        if object_ids.is_empty() {
            return Ok(());
        }
        let connection = self.connection()?;
        let table_name = table_name(entity, architecture);
        let table = match self
            .runtime
            .block_on(connection.open_table(&table_name).execute())
        {
            Ok(table) => table,
            Err(_) => return Ok(()),
        };
        for chunk in object_ids.chunks(UPSERT_ROWS_CHUNK_SIZE) {
            let rows = chunk
                .iter()
                .map(|object_id| Row {
                    object_id: object_id.clone(),
                    sha256: None,
                    address: None,
                    occurrences_json: String::new(),
                    vector: Vec::new(),
                })
                .collect::<Vec<_>>();
            let delete_predicate = delete_predicate_for_rows(&rows);
            if delete_predicate.is_empty() {
                continue;
            }
            self.runtime
                .block_on(table.delete(&delete_predicate))
                .map_err(|error| Error::Lance(error.to_string()))?;
        }
        Ok(())
    }

    pub fn search(
        &self,
        entity: Collection,
        architecture: &str,
        vector: &[f32],
        limit: usize,
    ) -> Result<Vec<Row>, Error> {
        let connection = self.connection()?;
        let table_name = table_name(entity, architecture);
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
        Ok(dedupe_rows_by_object_id(rows))
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

const UPSERT_ROWS_CHUNK_SIZE: usize = 512;

fn schema_for_table(dims: i32) -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("object_id", DataType::Utf8, false),
        Field::new("sha256", DataType::Utf8, true),
        Field::new("address", DataType::UInt64, true),
        Field::new("occurrences", DataType::Utf8, false),
        Field::new(
            "vector",
            DataType::FixedSizeList(Arc::new(Field::new("item", DataType::Float32, true)), dims),
            true,
        ),
    ]))
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

fn record_batch_for_row(
    object_id: &str,
    sha256: Option<&str>,
    address: Option<u64>,
    vector: &[f32],
    occurrences_json: &str,
) -> Result<RecordBatch, Error> {
    let dims = i32::try_from(vector.len()).map_err(|error| Error::Arrow(error.to_string()))?;
    let schema = schema_for_table(dims);
    RecordBatch::try_new(
        schema,
        vec![
            Arc::new(StringArray::from(vec![object_id])),
            Arc::new(StringArray::from(vec![sha256])),
            Arc::new(UInt64Array::from(vec![address])),
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

fn record_batch_for_rows(rows: &[Row]) -> Result<RecordBatch, Error> {
    let dims =
        i32::try_from(rows[0].vector.len()).map_err(|error| Error::Arrow(error.to_string()))?;
    let schema = schema_for_table(dims);
    let object_ids = rows
        .iter()
        .map(|row| row.object_id.as_str())
        .collect::<Vec<_>>();
    let sha256_values = rows
        .iter()
        .map(|row| row.sha256.as_deref())
        .collect::<Vec<_>>();
    let addresses = rows.iter().map(|row| row.address).collect::<Vec<_>>();
    let occurrences = rows
        .iter()
        .map(|row| row.occurrences_json.as_str())
        .collect::<Vec<_>>();
    let vectors = rows
        .iter()
        .map(|row| Some(row.vector.iter().copied().map(Some).collect::<Vec<_>>()))
        .collect::<Vec<_>>();
    RecordBatch::try_new(
        schema,
        vec![
            Arc::new(StringArray::from(object_ids)),
            Arc::new(StringArray::from(sha256_values)),
            Arc::new(UInt64Array::from(addresses)),
            Arc::new(StringArray::from(occurrences)),
            Arc::new(FixedSizeListArray::from_iter_primitive::<
                arrow_array::types::Float32Type,
                _,
                _,
            >(vectors, dims)),
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
    let sha256s = batch
        .column_by_name("sha256")
        .and_then(|column| column.as_any().downcast_ref::<StringArray>());
    let addresses = batch
        .column_by_name("address")
        .and_then(|column| column.as_any().downcast_ref::<UInt64Array>());
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
            sha256: sha256s.and_then(|values| {
                if values.is_null(index) {
                    None
                } else {
                    Some(values.value(index).to_string())
                }
            }),
            address: addresses.and_then(|values| {
                if values.is_null(index) {
                    None
                } else {
                    Some(values.value(index))
                }
            }),
            occurrences_json: occurrences.value(index).to_string(),
            vector,
        });
    }
    Ok(rows)
}

fn dedupe_rows_by_object_id(rows: Vec<Row>) -> Vec<Row> {
    let mut unique = BTreeMap::<String, Row>::new();
    for row in rows {
        unique.insert(row.object_id.clone(), row);
    }
    unique.into_values().collect()
}

fn dedupe_input_rows(rows: &[Row]) -> Vec<Row> {
    let mut unique = BTreeMap::<String, Row>::new();
    for row in rows {
        unique.insert(row.object_id.clone(), row.clone());
    }
    unique.into_values().collect()
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

fn table_name(entity: Collection, architecture: &str) -> String {
    format!("{}__{}", entity.as_str(), architecture)
}

fn delete_predicate_for_rows(rows: &[Row]) -> String {
    rows.iter()
        .map(|row| format!("object_id = '{}'", row.object_id.replace('\'', "''")))
        .collect::<Vec<_>>()
        .join(" OR ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upsert_and_search_round_trip() {
        let root = std::env::temp_dir().join(format!("binlex-lancedb-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let client = LanceDB::new(&root).expect("create lancedb client");

        client
            .upsert(
                Collection::Instruction,
                "x86_64",
                "instruction:abc",
                Some("deadbeef"),
                Some(4096),
                &[1.0, 0.0, 0.0],
                r#"[{"sha256":"deadbeef","address":4096}]"#,
            )
            .expect("upsert row");

        let rows = client
            .search(Collection::Instruction, "x86_64", &[1.0, 0.0, 0.0], 4)
            .expect("search rows");

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].object_id, "instruction:abc");
        assert_eq!(rows[0].sha256.as_deref(), Some("deadbeef"));
        assert_eq!(rows[0].address, Some(4096));
        assert_eq!(
            rows[0].occurrences_json,
            r#"[{"sha256":"deadbeef","address":4096}]"#
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn repeat_upsert_does_not_duplicate_search_rows() {
        let root = std::env::temp_dir().join(format!(
            "binlex-lancedb-repeat-upsert-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let client = LanceDB::new(&root).expect("create lancedb client");

        for _ in 0..3 {
            client
                .upsert(
                    Collection::Function,
                    "amd64",
                    "function:repeat",
                    Some("repeat-sha"),
                    Some(4096),
                    &[1.0, 0.0, 0.0],
                    r#"[{"sha256":"repeat-sha","address":4096,"corpora":["default"]}]"#,
                )
                .expect("upsert repeated row");
        }

        let rows = client
            .search(Collection::Function, "amd64", &[1.0, 0.0, 0.0], 8)
            .expect("search repeated row");

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].object_id, "function:repeat");

        let _ = std::fs::remove_dir_all(&root);
    }
}
