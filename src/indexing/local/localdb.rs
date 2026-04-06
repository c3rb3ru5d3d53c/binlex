use super::LocalIndex;
use super::support::sample_key;
use super::types::{
    CollectionCommentRecord, CollectionCommentSearchPage, CollectionTagRecord,
    CollectionTagSearchPage, CommentRecord, CommentSearchPage, Error, SampleStatusRecord,
    StoredGraphRecord, TagRecord, TagSearchPage,
};
use crate::controlflow::{Block, Function, Graph, Instruction};
use crate::databases::{LocalDBPage, SampleCommentRecord, SampleTagRecord};
use crate::indexing::Collection;
use chrono::Utc;
use std::collections::BTreeMap;

impl LocalIndex {
    pub fn sample_tag_add(&self, sha256: &str, tag: &str) -> Result<(), Error> {
        let sha256 = self.ensure_sample_exists(sha256)?;
        let tag = tag.trim();
        if tag.is_empty() {
            return Err(Error::Validation("tag must not be empty".to_string()));
        }
        self.localdb
            .sample_tag_add(&SampleTagRecord {
                sha256,
                tag: tag.to_string(),
                timestamp: Utc::now().to_rfc3339(),
            })
            .map_err(|error| Error::LocalDb(error.to_string()))
    }

    pub fn sample_tag_remove(&self, sha256: &str, tag: &str) -> Result<(), Error> {
        let sha256 = self.ensure_sample_exists(sha256)?;
        let tag = tag.trim();
        if tag.is_empty() {
            return Err(Error::Validation("tag must not be empty".to_string()));
        }
        self.localdb
            .sample_tag_remove(&sha256, tag)
            .map_err(|error| Error::LocalDb(error.to_string()))
    }

    pub fn sample_tag_replace(&self, sha256: &str, tags: &[String]) -> Result<(), Error> {
        let sha256 = self.ensure_sample_exists(sha256)?;
        let tags = tags
            .iter()
            .map(|tag| tag.trim().to_string())
            .filter(|tag| !tag.is_empty())
            .collect::<Vec<_>>();
        self.localdb
            .sample_tag_replace(&sha256, &tags, &Utc::now().to_rfc3339())
            .map_err(|error| Error::LocalDb(error.to_string()))
    }

    pub fn sample_tag_search(
        &self,
        query: &str,
        page: usize,
        page_size: usize,
    ) -> Result<TagSearchPage, Error> {
        self.localdb
            .sample_tag_search(query, page, page_size)
            .map(tag_page_from_localdb)
            .map_err(|error| Error::LocalDb(error.to_string()))
    }

    pub fn tag_add(&self, tag: &str) -> Result<(), Error> {
        let tag = tag.trim();
        if tag.is_empty() {
            return Err(Error::Validation("tag must not be empty".to_string()));
        }
        self.localdb
            .tag_add(tag, Some(&Utc::now().to_rfc3339()), None)
            .map_err(|error| Error::LocalDb(error.to_string()))
    }

    pub fn tag_search(&self, query: &str, limit: usize) -> Result<Vec<String>, Error> {
        self.localdb
            .tag_search(query, limit)
            .map(|page| page.items.into_iter().map(|item| item.tag).collect())
            .map_err(|error| Error::LocalDb(error.to_string()))
    }

    pub fn sample_tag_list(&self, sha256: &str) -> Result<Vec<String>, Error> {
        let sha256 = self.ensure_sample_exists(sha256)?;
        self.localdb
            .sample_tag_list(&sha256)
            .map_err(|error| Error::LocalDb(error.to_string()))
    }

    pub fn collection_tag_add(
        &self,
        sha256: &str,
        collection: Collection,
        address: u64,
        tag: &str,
        username: &str,
    ) -> Result<(), Error> {
        let sha256 = self.ensure_collection_member_exists(sha256, collection, address)?;
        let tag = tag.trim();
        if tag.is_empty() {
            return Err(Error::Validation("tag must not be empty".to_string()));
        }
        self.localdb
            .tag_add(tag, Some(&Utc::now().to_rfc3339()), Some(username))
            .map_err(|error| Error::LocalDb(error.to_string()))?;
        self.localdb
            .collection_tag_add(&CollectionTagRecord {
                sha256,
                collection,
                address,
                tag: tag.to_string(),
                username: username.to_string(),
                timestamp: Utc::now().to_rfc3339(),
            })
            .map_err(|error| Error::LocalDb(error.to_string()))
    }

    pub fn collection_tag_remove(
        &self,
        sha256: &str,
        collection: Collection,
        address: u64,
        tag: &str,
    ) -> Result<(), Error> {
        let sha256 = self.ensure_collection_member_exists(sha256, collection, address)?;
        let tag = tag.trim();
        if tag.is_empty() {
            return Err(Error::Validation("tag must not be empty".to_string()));
        }
        self.localdb
            .collection_tag_remove(&sha256, collection, address, tag)
            .map_err(|error| Error::LocalDb(error.to_string()))
    }

    pub fn collection_tag_replace(
        &self,
        sha256: &str,
        collection: Collection,
        address: u64,
        tags: &[String],
        username: &str,
    ) -> Result<(), Error> {
        let sha256 = self.ensure_collection_member_exists(sha256, collection, address)?;
        let tags = tags
            .iter()
            .map(|tag| tag.trim().to_string())
            .filter(|tag| !tag.is_empty())
            .collect::<Vec<_>>();
        self.localdb
            .collection_tag_replace(
                &sha256,
                collection,
                address,
                &tags,
                username,
                &Utc::now().to_rfc3339(),
            )
            .map_err(|error| Error::LocalDb(error.to_string()))
    }

    pub fn collection_tag_search(
        &self,
        query: &str,
        collection: Option<Collection>,
        page: usize,
        page_size: usize,
    ) -> Result<CollectionTagSearchPage, Error> {
        self.localdb
            .collection_tag_search(query, collection, page, page_size)
            .map(collection_tag_page_from_localdb)
            .map_err(|error| Error::LocalDb(error.to_string()))
    }

    pub fn collection_tag_list(
        &self,
        sha256: &str,
        collection: Collection,
        address: u64,
    ) -> Result<Vec<String>, Error> {
        let sha256 = self.ensure_collection_member_exists(sha256, collection, address)?;
        self.localdb
            .collection_tag_list(&sha256, collection, address)
            .map_err(|error| Error::LocalDb(error.to_string()))
    }

    pub fn collection_tag_details_list(
        &self,
        sha256: &str,
        collection: Collection,
        address: u64,
    ) -> Result<Vec<CollectionTagRecord>, Error> {
        let sha256 = self.ensure_collection_member_exists(sha256, collection, address)?;
        self.localdb
            .collection_tag_details_list(&sha256, collection, address)
            .map_err(|error| Error::LocalDb(error.to_string()))
    }

    pub fn collection_tag_count(
        &self,
        sha256: &str,
        collection: Collection,
        address: u64,
    ) -> Result<usize, Error> {
        let sha256 = self.ensure_collection_member_exists(sha256, collection, address)?;
        self.localdb
            .collection_tag_count(&sha256, collection, address)
            .map_err(|error| Error::LocalDb(error.to_string()))
    }

    pub fn collection_tag_counts(
        &self,
        keys: &[(String, Collection, u64)],
    ) -> Result<BTreeMap<(String, Collection, u64), usize>, Error> {
        self.localdb
            .collection_tag_counts(keys)
            .map_err(|error| Error::LocalDb(error.to_string()))
    }

    pub fn sample_comment_add(
        &self,
        sha256: &str,
        comment: &str,
        timestamp: Option<&str>,
    ) -> Result<(), Error> {
        let sha256 = self.ensure_sample_exists(sha256)?;
        let comment = comment.trim();
        if comment.is_empty() {
            return Err(Error::Validation("comment must not be empty".to_string()));
        }
        self.localdb
            .sample_comment_add(&sha256, comment, timestamp)
            .map_err(|error| Error::LocalDb(error.to_string()))
    }

    pub fn sample_comment_remove(&self, sha256: &str, comment: &str) -> Result<(), Error> {
        let sha256 = self.ensure_sample_exists(sha256)?;
        let comment = comment.trim();
        if comment.is_empty() {
            return Err(Error::Validation("comment must not be empty".to_string()));
        }
        self.localdb
            .sample_comment_remove(&sha256, comment)
            .map_err(|error| Error::LocalDb(error.to_string()))
    }

    pub fn sample_comment_replace(
        &self,
        sha256: &str,
        comments: &[String],
        timestamp: Option<&str>,
    ) -> Result<(), Error> {
        let sha256 = self.ensure_sample_exists(sha256)?;
        let comments = comments
            .iter()
            .map(|comment| comment.trim().to_string())
            .filter(|comment| !comment.is_empty())
            .collect::<Vec<_>>();
        self.localdb
            .sample_comment_replace(&sha256, &comments, timestamp)
            .map_err(|error| Error::LocalDb(error.to_string()))
    }

    pub fn sample_comment_search(
        &self,
        query: &str,
        page: usize,
        page_size: usize,
    ) -> Result<CommentSearchPage, Error> {
        self.localdb
            .sample_comment_search(query, page, page_size)
            .map(comment_page_from_localdb)
            .map_err(|error| Error::LocalDb(error.to_string()))
    }

    pub fn collection_comment_add(
        &self,
        sha256: &str,
        collection: Collection,
        address: u64,
        comment: &str,
        timestamp: Option<&str>,
    ) -> Result<(), Error> {
        let sha256 = self.ensure_collection_member_exists(sha256, collection, address)?;
        let comment = comment.trim();
        if comment.is_empty() {
            return Err(Error::Validation("comment must not be empty".to_string()));
        }
        self.localdb
            .collection_comment_add(&sha256, collection, address, comment, timestamp)
            .map_err(|error| Error::LocalDb(error.to_string()))
    }

    pub fn collection_comment_remove(
        &self,
        sha256: &str,
        collection: Collection,
        address: u64,
        comment: &str,
    ) -> Result<(), Error> {
        let sha256 = self.ensure_collection_member_exists(sha256, collection, address)?;
        let comment = comment.trim();
        if comment.is_empty() {
            return Err(Error::Validation("comment must not be empty".to_string()));
        }
        self.localdb
            .collection_comment_remove(&sha256, collection, address, comment)
            .map_err(|error| Error::LocalDb(error.to_string()))
    }

    pub fn collection_comment_replace(
        &self,
        sha256: &str,
        collection: Collection,
        address: u64,
        comments: &[String],
        timestamp: Option<&str>,
    ) -> Result<(), Error> {
        let sha256 = self.ensure_collection_member_exists(sha256, collection, address)?;
        let comments = comments
            .iter()
            .map(|comment| comment.trim().to_string())
            .filter(|comment| !comment.is_empty())
            .collect::<Vec<_>>();
        self.localdb
            .collection_comment_replace(&sha256, collection, address, &comments, timestamp)
            .map_err(|error| Error::LocalDb(error.to_string()))
    }

    pub fn collection_comment_search(
        &self,
        query: &str,
        collection: Option<Collection>,
        page: usize,
        page_size: usize,
    ) -> Result<CollectionCommentSearchPage, Error> {
        self.localdb
            .collection_comment_search(query, collection, page, page_size)
            .map(collection_comment_page_from_localdb)
            .map_err(|error| Error::LocalDb(error.to_string()))
    }

    pub fn sample_status_get(&self, sha256: &str) -> Result<Option<SampleStatusRecord>, Error> {
        let sha256 = sha256.trim();
        if sha256.is_empty() {
            return Err(Error::Validation("sha256 must not be empty".to_string()));
        }
        self.localdb
            .sample_status_get(sha256)
            .map_err(|error| Error::LocalDb(error.to_string()))
    }

    pub fn sample_status_set(
        &self,
        sha256: &str,
        status: crate::databases::SampleStatus,
        timestamp: Option<&str>,
        id: Option<&str>,
        error_message: Option<&str>,
    ) -> Result<(), Error> {
        let sha256 = self.ensure_sample_exists(sha256)?;
        self.localdb
            .sample_status_set(&SampleStatusRecord {
                sha256,
                status,
                timestamp: timestamp
                    .map(ToString::to_string)
                    .unwrap_or_else(|| chrono::Utc::now().to_rfc3339()),
                error_message: error_message.map(ToString::to_string),
                id: id.map(ToString::to_string),
            })
            .map_err(|error| Error::LocalDb(error.to_string()))
    }

    pub fn sample_status_delete(&self, sha256: &str) -> Result<(), Error> {
        let sha256 = sha256.trim();
        if sha256.is_empty() {
            return Err(Error::Validation("sha256 must not be empty".to_string()));
        }
        self.localdb
            .sample_status_delete(sha256)
            .map_err(|error| Error::LocalDb(error.to_string()))
    }

    fn ensure_sample_exists(&self, sha256: &str) -> Result<String, Error> {
        let sha256 = sha256.trim();
        if sha256.is_empty() {
            return Err(Error::Validation("sha256 must not be empty".to_string()));
        }
        if !self
            .store
            .object_exists(&sample_key(sha256))
            .map_err(|error| Error::LocalStore(error.to_string()))?
        {
            return Err(Error::NotFound(format!("sample {}", sha256)));
        }
        Ok(sha256.to_string())
    }

    fn ensure_collection_member_exists(
        &self,
        sha256: &str,
        collection: Collection,
        address: u64,
    ) -> Result<String, Error> {
        let sha256 = self.ensure_sample_exists(sha256)?;
        if self.collection_member_exists(&sha256, collection, address)? {
            Ok(sha256)
        } else {
            Err(Error::NotFound(format!(
                "{} {} in sample {}",
                collection.as_str(),
                address,
                sha256
            )))
        }
    }

    fn collection_member_exists(
        &self,
        sha256: &str,
        collection: Collection,
        address: u64,
    ) -> Result<bool, Error> {
        let keys = self
            .store
            .object_list("index/")
            .map_err(|error| Error::LocalStore(error.to_string()))?;
        for key in keys {
            let entry = self
                .store
                .object_get_json::<super::types::IndexEntry>(&key)
                .map_err(|error| Error::LocalStore(error.to_string()))?;
            if entry.sha256 == sha256 && entry.entity == collection && entry.address == address {
                return Ok(true);
            }
        }

        if let Some(graph) = self.load_stored_graph(sha256)? {
            let exists = match collection {
                Collection::Function => Function::new(address, &graph).is_ok(),
                Collection::Block => Block::new(address, &graph).is_ok(),
                Collection::Instruction => Instruction::new(address, &graph).is_ok(),
            };
            if exists {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn load_stored_graph(&self, sha256: &str) -> Result<Option<Graph>, Error> {
        match self
            .store
            .object_get_json::<StoredGraphRecord>(&super::support::graph_key(sha256))
        {
            Ok(record) => Graph::from_snapshot(record.snapshot, self.config.clone())
                .map(Some)
                .map_err(|error| Error::Graph(error.to_string())),
            Err(crate::storage::localstore::Error::NotFound(_)) => Ok(None),
            Err(error) => Err(Error::LocalStore(error.to_string())),
        }
    }
}

fn tag_page_from_localdb(page: LocalDBPage<SampleTagRecord>) -> TagSearchPage {
    TagSearchPage {
        items: page
            .items
            .into_iter()
            .map(|item| TagRecord {
                sha256: item.sha256,
                tag: item.tag,
                timestamp: item.timestamp,
            })
            .collect(),
        page: page.page,
        page_size: page.page_size,
        has_next: page.has_next,
    }
}

fn comment_page_from_localdb(page: LocalDBPage<SampleCommentRecord>) -> CommentSearchPage {
    CommentSearchPage {
        items: page
            .items
            .into_iter()
            .map(|item| CommentRecord {
                sha256: item.sha256,
                comment: item.comment,
                timestamp: item.timestamp,
            })
            .collect(),
        page: page.page,
        page_size: page.page_size,
        has_next: page.has_next,
    }
}

fn collection_tag_page_from_localdb(
    page: LocalDBPage<CollectionTagRecord>,
) -> CollectionTagSearchPage {
    CollectionTagSearchPage {
        items: page.items,
        page: page.page,
        page_size: page.page_size,
        has_next: page.has_next,
    }
}

fn collection_comment_page_from_localdb(
    page: LocalDBPage<CollectionCommentRecord>,
) -> CollectionCommentSearchPage {
    CollectionCommentSearchPage {
        items: page.items,
        page: page.page,
        page_size: page.page_size,
        has_next: page.has_next,
    }
}
