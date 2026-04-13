use super::*;

impl LocalDB {
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
}
