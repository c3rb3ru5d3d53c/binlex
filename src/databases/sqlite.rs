use rusqlite::Connection;
use rusqlite::params_from_iter;
use rusqlite::types::ValueRef;
use rusqlite::types::{ToSql, ToSqlOutput};
use serde_json::{Map, Number, Value};
use std::fmt;
use std::path::Path;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

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

#[derive(Debug, Clone, PartialEq)]
pub enum SQLiteValue {
    Null,
    Integer(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

impl ToSql for SQLiteValue {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(match self {
            Self::Null => ToSqlOutput::Owned(rusqlite::types::Value::Null),
            Self::Integer(value) => ToSqlOutput::Owned(rusqlite::types::Value::Integer(*value)),
            Self::Real(value) => ToSqlOutput::Owned(rusqlite::types::Value::Real(*value)),
            Self::Text(value) => ToSqlOutput::Owned(rusqlite::types::Value::Text(value.clone())),
            Self::Blob(value) => ToSqlOutput::Owned(rusqlite::types::Value::Blob(value.clone())),
        })
    }
}

pub struct SQLite {
    path: PathBuf,
    connection: Mutex<Connection>,
}

impl SQLite {
    pub fn new(path: &Path) -> Result<Self, Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| Error(error.to_string()))?;
        }
        let connection = Connection::open(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            connection: Mutex::new(connection),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn execute_batch(&self, sql: &str) -> Result<(), Error> {
        let connection = self.connection()?;
        connection.execute_batch(sql)?;
        Ok(())
    }

    pub fn execute(&self, sql: &str, params: &[SQLiteValue]) -> Result<usize, Error> {
        let connection = self.connection()?;
        Ok(connection.execute(sql, params_from_iter(params.iter()))?)
    }

    pub fn query(
        &self,
        sql: &str,
        params: &[SQLiteValue],
    ) -> Result<Vec<Map<String, Value>>, Error> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(sql)?;
        let column_names = statement
            .column_names()
            .into_iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        let mut rows = statement.query(params_from_iter(params.iter()))?;
        let mut output = Vec::new();
        while let Some(row) = rows.next()? {
            let mut object = Map::new();
            for (index, name) in column_names.iter().enumerate() {
                object.insert(name.clone(), value_ref_to_json(row.get_ref(index)?));
            }
            output.push(object);
        }
        Ok(output)
    }

    pub(crate) fn connection(&self) -> Result<MutexGuard<'_, Connection>, Error> {
        self.connection
            .lock()
            .map_err(|_| Error("sqlite connection mutex poisoned".to_string()))
    }
}

fn value_ref_to_json(value: ValueRef<'_>) -> Value {
    match value {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(value) => Value::Number(Number::from(value)),
        ValueRef::Real(value) => Number::from_f64(value)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        ValueRef::Text(value) => Value::String(String::from_utf8_lossy(value).into_owned()),
        ValueRef::Blob(value) => Value::Array(
            value
                .iter()
                .map(|byte| Value::Number(Number::from(*byte)))
                .collect(),
        ),
    }
}
