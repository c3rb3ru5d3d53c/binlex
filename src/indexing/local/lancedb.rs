use crate::databases::lancedb::{Error, LanceDB};
use crate::indexing::Collection;
use arrow_array::{Array, FixedSizeListArray, Float32Array, RecordBatch, StringArray, UInt64Array};
use arrow_schema::{DataType, Field, Schema};
use std::collections::BTreeMap;
use std::sync::Arc;

const UPSERT_ROWS_CHUNK_SIZE: usize = 512;

#[derive(Clone, Debug)]
pub(super) struct Row {
    pub object_id: String,
    pub username: String,
    pub sha256: Option<String>,
    pub address: Option<u64>,
    pub vector: Vec<f32>,
}

pub(super) fn table_name(entity: Collection, architecture: &str) -> String {
    format!("{}__{}", entity.as_str(), architecture)
}

pub(super) fn upsert_rows(
    db: &LanceDB,
    entity: Collection,
    architecture: &str,
    rows: &[Row],
) -> Result<(), Error> {
    if rows.is_empty() {
        return Ok(());
    }
    let table_name = table_name(entity, architecture);
    let deduped = dedupe_input_rows(rows);
    let schema = schema_for_table(
        i32::try_from(deduped[0].vector.len()).map_err(|error| Error::Arrow(error.to_string()))?,
    );
    let batches = deduped
        .chunks(UPSERT_ROWS_CHUNK_SIZE)
        .map(record_batch_for_rows)
        .collect::<Result<Vec<_>, _>>()?;
    db.upsert_batches(&table_name, schema, &["object_id"], batches)
}

#[allow(dead_code)]
pub(super) fn delete_objects(
    db: &LanceDB,
    entity: Collection,
    architecture: &str,
    object_ids: &[String],
) -> Result<(), Error> {
    if object_ids.is_empty() {
        return Ok(());
    }
    let table_name = table_name(entity, architecture);
    for chunk in object_ids.chunks(UPSERT_ROWS_CHUNK_SIZE) {
        let rows = chunk
            .iter()
            .map(|object_id| Row {
                object_id: object_id.clone(),
                username: "anonymous".to_string(),
                sha256: None,
                address: None,
                vector: Vec::new(),
            })
            .collect::<Vec<_>>();
        let predicate = delete_predicate_for_rows(&rows);
        if predicate.is_empty() {
            continue;
        }
        db.delete_where(&table_name, &predicate)?;
    }
    Ok(())
}

pub(super) fn search(
    db: &LanceDB,
    entity: Collection,
    architecture: &str,
    vector: &[f32],
    limit: usize,
) -> Result<Vec<Row>, Error> {
    let table_name = table_name(entity, architecture);
    let batches = db.vector_search(&table_name, vector, limit)?;
    let mut rows = Vec::new();
    for batch in batches {
        rows.extend(rows_from_batch(&batch)?);
    }
    Ok(dedupe_rows_by_object_id(rows))
}

fn schema_for_table(dims: i32) -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("object_id", DataType::Utf8, false),
        Field::new("username", DataType::Utf8, false),
        Field::new("sha256", DataType::Utf8, true),
        Field::new("address", DataType::UInt64, true),
        Field::new(
            "vector",
            DataType::FixedSizeList(Arc::new(Field::new("item", DataType::Float32, true)), dims),
            true,
        ),
    ]))
}

fn record_batch_for_rows(rows: &[Row]) -> Result<RecordBatch, Error> {
    let dims =
        i32::try_from(rows[0].vector.len()).map_err(|error| Error::Arrow(error.to_string()))?;
    let schema = schema_for_table(dims);
    let object_ids = rows
        .iter()
        .map(|row| row.object_id.as_str())
        .collect::<Vec<_>>();
    let usernames = rows
        .iter()
        .map(|row| row.username.as_str())
        .collect::<Vec<_>>();
    let sha256_values = rows
        .iter()
        .map(|row| row.sha256.as_deref())
        .collect::<Vec<_>>();
    let addresses = rows.iter().map(|row| row.address).collect::<Vec<_>>();
    let vectors = rows
        .iter()
        .map(|row| Some(row.vector.iter().copied().map(Some).collect::<Vec<_>>()))
        .collect::<Vec<_>>();
    RecordBatch::try_new(
        schema,
        vec![
            Arc::new(StringArray::from(object_ids)),
            Arc::new(StringArray::from(usernames)),
            Arc::new(StringArray::from(sha256_values)),
            Arc::new(UInt64Array::from(addresses)),
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
    let usernames = batch
        .column_by_name("username")
        .ok_or_else(|| Error::Arrow("missing username column".to_string()))?
        .as_any()
        .downcast_ref::<StringArray>()
        .ok_or_else(|| Error::Arrow("username column type mismatch".to_string()))?;
    let addresses = batch
        .column_by_name("address")
        .and_then(|column| column.as_any().downcast_ref::<UInt64Array>());
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
            username: usernames.value(index).to_string(),
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

        upsert_rows(
            &client,
            Collection::Instruction,
            "x86_64",
            &[Row {
                object_id: "instruction:abc".to_string(),
                username: "anonymous".to_string(),
                sha256: Some("deadbeef".to_string()),
                address: Some(4096),
                vector: vec![1.0, 0.0, 0.0],
            }],
        )
        .expect("upsert row");

        let rows = search(
            &client,
            Collection::Instruction,
            "x86_64",
            &[1.0, 0.0, 0.0],
            4,
        )
        .expect("search rows");

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].object_id, "instruction:abc");
        assert_eq!(rows[0].sha256.as_deref(), Some("deadbeef"));
        assert_eq!(rows[0].address, Some(4096));

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
            upsert_rows(
                &client,
                Collection::Function,
                "amd64",
                &[Row {
                    object_id: "function:repeat".to_string(),
                    username: "anonymous".to_string(),
                    sha256: Some("repeat-sha".to_string()),
                    address: Some(4096),
                    vector: vec![1.0, 0.0, 0.0],
                }],
            )
            .expect("upsert repeated row");
        }

        let rows = search(&client, Collection::Function, "amd64", &[1.0, 0.0, 0.0], 8)
            .expect("search repeated row");

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].object_id, "function:repeat");

        let _ = std::fs::remove_dir_all(&root);
    }
}
