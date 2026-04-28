use super::LocalIndex;
use super::support::validate_corpus_sha256;
use super::types::{Error, StoredGraphRecord};
use crate::controlflow::Graph;
use crate::storage::localstore;

impl LocalIndex {
    pub fn sample_put(&self, data: &[u8]) -> Result<String, Error> {
        self.store
            .sample_put(data)
            .map_err(|error| Error::LocalStore(error.to_string()))
    }

    pub fn sample_get(&self, sha256: &str) -> Result<Vec<u8>, Error> {
        self.store.sample_get(sha256).map_err(|error| match error {
            localstore::Error::NotFound(_) => Error::NotFound(format!("sample {}", sha256)),
            other => Error::LocalStore(other.to_string()),
        })
    }

    pub fn sample_load(&self, corpus: &str, sha256: &str) -> Result<Graph, Error> {
        validate_corpus_sha256(corpus, sha256)?;
        let record: StoredGraphRecord =
            self.store
                .sample_json_get(sha256, "graph")
                .map_err(|error| match error {
                    localstore::Error::NotFound(_) => {
                        Error::NotFound(format!("graph {}/{}", corpus, sha256))
                    }
                    other => Error::LocalStore(other.to_string()),
                })?;
        Graph::from_snapshot(record.snapshot, self.config.clone())
            .map_err(|error| Error::Graph(error.to_string()))
    }

    pub fn project_put(&self, sha256: &str, data: &[u8]) -> Result<(), Error> {
        self.store
            .project_put(sha256, data)
            .map_err(|error| Error::LocalStore(error.to_string()))
    }

    pub fn project_get(&self, sha256: &str) -> Result<Vec<u8>, Error> {
        self.store.project_get(sha256).map_err(|error| match error {
            localstore::Error::NotFound(_) => Error::NotFound(format!("project {}", sha256)),
            other => Error::LocalStore(other.to_string()),
        })
    }
}
