use super::*;

impl LocalDB {
    pub fn tag_add(
        &self,
        tag: &str,
        timestamp: Option<&str>,
        username: Option<&str>,
    ) -> Result<(), Error> {
        let tag = normalize_metadata_name("tag", tag)?;
        let timestamp = timestamp
            .map(ToString::to_string)
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
        let username = username.unwrap_or_default().trim().to_string();
        self.sqlite.execute(
            "INSERT INTO tags (tag, username, timestamp)
             VALUES (?1, ?2, ?3)
            ON CONFLICT(tag) DO UPDATE SET
              username = excluded.username,
              timestamp = excluded.timestamp",
            &[
                SQLiteValue::Text(tag),
                SQLiteValue::Text(username),
                SQLiteValue::Text(timestamp),
            ],
        )?;
        Ok(())
    }

    pub fn tag_search(&self, query: &str, limit: usize) -> Result<TagCatalogSearchPage, Error> {
        let limit = limit.max(1);
        let pattern = if query.trim().is_empty() {
            "%".to_string()
        } else {
            format!("%{}%", query.trim().to_ascii_lowercase())
        };
        let total_rows = self.sqlite.query(
            "SELECT COUNT(*) AS count
             FROM tags
             WHERE LOWER(tag) LIKE ?1",
            &[SQLiteValue::Text(pattern.clone())],
        )?;
        let total_results = total_rows
            .into_iter()
            .next()
            .and_then(|row| row.get("count").and_then(|value| value.as_i64()))
            .unwrap_or(0)
            .max(0) as usize;
        let rows = self.sqlite.query(
            "SELECT tag, username, timestamp
             FROM tags
             WHERE LOWER(tag) LIKE ?1
             ORDER BY tag ASC
             LIMIT ?2",
            &[
                SQLiteValue::Text(pattern),
                SQLiteValue::Integer(limit as i64),
            ],
        )?;
        let items = rows
            .into_iter()
            .map(|row| -> Result<TagCatalogRecord, Error> {
                Ok(TagCatalogRecord {
                    tag: row
                        .get("tag")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| Error("tag row is missing tag".to_string()))?
                        .to_string(),
                    username: row
                        .get("username")
                        .and_then(|value| value.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    timestamp: row
                        .get("timestamp")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| Error("tag row is missing timestamp".to_string()))?
                        .to_string(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(TagCatalogSearchPage {
            has_next: total_results > items.len(),
            total_results,
            items,
        })
    }

    pub fn tag_get(&self, tag: &str) -> Result<Option<TagCatalogRecord>, Error> {
        let rows = self.sqlite.query(
            "SELECT tag, username, timestamp
             FROM tags
             WHERE tag = ?1
             LIMIT 1",
            &[SQLiteValue::Text(tag.trim().to_string())],
        )?;
        rows.into_iter()
            .next()
            .map(|row| {
                Ok(TagCatalogRecord {
                    tag: row
                        .get("tag")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| Error("tag row is missing tag".to_string()))?
                        .to_string(),
                    username: row
                        .get("username")
                        .and_then(|value| value.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    timestamp: row
                        .get("timestamp")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| Error("tag row is missing timestamp".to_string()))?
                        .to_string(),
                })
            })
            .transpose()
    }

    pub fn tag_delete_global(&self, tag: &str) -> Result<bool, Error> {
        let tag = normalize_metadata_name("tag", tag)?;
        self.sqlite.execute(
            "DELETE FROM collection_tags WHERE tag = ?1",
            &[SQLiteValue::Text(tag.clone())],
        )?;
        self.sqlite.execute(
            "DELETE FROM tags WHERE tag = ?1",
            &[SQLiteValue::Text(tag.clone())],
        )?;
        let rows = self.sqlite.query(
            "SELECT tag FROM tags WHERE tag = ?1 LIMIT 1",
            &[SQLiteValue::Text(tag)],
        )?;
        Ok(rows.is_empty())
    }

    pub fn collection_tag_add(&self, tag: &CollectionTagRecord) -> Result<(), Error> {
        self.tag_add(&tag.tag, Some(&tag.timestamp), Some(&tag.username))?;
        self.sqlite.execute(
            "INSERT INTO collection_tags (sha256, collection, address, tag, username, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(sha256, collection, address, tag) DO UPDATE SET
               username = excluded.username,
               timestamp = excluded.timestamp",
            &[
                SQLiteValue::Text(tag.sha256.clone()),
                SQLiteValue::Text(tag.collection.as_str().to_string()),
                SQLiteValue::Integer(tag.address as i64),
                SQLiteValue::Text(tag.tag.clone()),
                SQLiteValue::Text(tag.username.clone()),
                SQLiteValue::Text(tag.timestamp.clone()),
            ],
        )?;
        Ok(())
    }

    pub fn collection_tag_add_many(&self, tags: &[CollectionTagRecord]) -> Result<(), Error> {
        if tags.is_empty() {
            return Ok(());
        }

        let mut connection = self.sqlite.connection()?;
        let transaction = connection.transaction()?;

        {
            let mut tag_upsert = transaction.prepare(
                "INSERT INTO tags (tag, username, timestamp)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(tag) DO UPDATE SET
                   username = excluded.username,
                   timestamp = excluded.timestamp",
            )?;
            let mut collection_tag_upsert = transaction.prepare(
                "INSERT INTO collection_tags (sha256, collection, address, tag, username, timestamp)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(sha256, collection, address, tag) DO UPDATE SET
                   username = excluded.username,
                   timestamp = excluded.timestamp",
            )?;

            for record in tags {
                let tag = normalize_metadata_name("tag", &record.tag)?;
                tag_upsert.execute((&tag, &record.username, &record.timestamp))?;
                collection_tag_upsert.execute((
                    &record.sha256,
                    record.collection.as_str(),
                    record.address as i64,
                    &tag,
                    &record.username,
                    &record.timestamp,
                ))?;
            }
        }

        transaction.commit()?;
        Ok(())
    }

    pub fn collection_tag_remove(
        &self,
        sha256: &str,
        collection: Collection,
        address: u64,
        tag: &str,
    ) -> Result<(), Error> {
        self.sqlite.execute(
            "DELETE FROM collection_tags
             WHERE sha256 = ?1 AND collection = ?2 AND address = ?3 AND tag = ?4",
            &[
                SQLiteValue::Text(sha256.to_string()),
                SQLiteValue::Text(collection.as_str().to_string()),
                SQLiteValue::Integer(address as i64),
                SQLiteValue::Text(tag.to_string()),
            ],
        )?;
        Ok(())
    }

    pub fn collection_tag_replace(
        &self,
        sha256: &str,
        collection: Collection,
        address: u64,
        tags: &[String],
        username: &str,
        timestamp: &str,
    ) -> Result<(), Error> {
        self.sqlite.execute(
            "DELETE FROM collection_tags WHERE sha256 = ?1 AND collection = ?2 AND address = ?3",
            &[
                SQLiteValue::Text(sha256.to_string()),
                SQLiteValue::Text(collection.as_str().to_string()),
                SQLiteValue::Integer(address as i64),
            ],
        )?;
        for tag in tags {
            self.collection_tag_add(&CollectionTagRecord {
                sha256: sha256.to_string(),
                collection,
                address,
                tag: tag.clone(),
                username: username.to_string(),
                timestamp: timestamp.to_string(),
            })?;
        }
        Ok(())
    }

    pub fn collection_tag_list(
        &self,
        sha256: &str,
        collection: Collection,
        address: u64,
    ) -> Result<Vec<String>, Error> {
        self.collection_tag_details_list(sha256, collection, address)
            .map(|items| items.into_iter().map(|item| item.tag).collect())
    }

    pub fn collection_tag_details_list(
        &self,
        sha256: &str,
        collection: Collection,
        address: u64,
    ) -> Result<Vec<CollectionTagRecord>, Error> {
        let rows = self.sqlite.query(
            "SELECT tag, username, timestamp
             FROM collection_tags
             WHERE sha256 = ?1 AND collection = ?2 AND address = ?3
             ORDER BY tag ASC",
            &[
                SQLiteValue::Text(sha256.to_string()),
                SQLiteValue::Text(collection.as_str().to_string()),
                SQLiteValue::Integer(address as i64),
            ],
        )?;
        rows.into_iter()
            .map(|row| {
                Ok(CollectionTagRecord {
                    sha256: sha256.to_string(),
                    collection,
                    address,
                    tag: row
                        .get("tag")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| Error("collection tag row is missing tag".to_string()))?
                        .to_string(),
                    username: row
                        .get("username")
                        .and_then(|value| value.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    timestamp: row
                        .get("timestamp")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| {
                            Error("collection tag row is missing timestamp".to_string())
                        })?
                        .to_string(),
                })
            })
            .collect()
    }

    pub fn collection_tag_count(
        &self,
        sha256: &str,
        collection: Collection,
        address: u64,
    ) -> Result<usize, Error> {
        let rows = self.sqlite.query(
            "SELECT COUNT(*) AS count
             FROM collection_tags
             WHERE sha256 = ?1 AND collection = ?2 AND address = ?3",
            &[
                SQLiteValue::Text(sha256.to_string()),
                SQLiteValue::Text(collection.as_str().to_string()),
                SQLiteValue::Integer(address as i64),
            ],
        )?;
        let Some(row) = rows.first() else {
            return Ok(0);
        };
        row.get("count")
            .and_then(|value| value.as_i64())
            .map(|value| value.max(0) as usize)
            .ok_or_else(|| Error("collection tag count row is missing count".to_string()))
    }

    pub fn collection_tag_counts(
        &self,
        keys: &[(String, Collection, u64)],
    ) -> Result<BTreeMap<(String, Collection, u64), usize>, Error> {
        let mut counts = BTreeMap::new();
        if keys.is_empty() {
            return Ok(counts);
        }
        let mut sql = String::from(
            "SELECT sha256, collection, address, COUNT(*) AS count
             FROM collection_tags
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
                .ok_or_else(|| Error("collection tag count row is missing sha256".to_string()))?
                .to_string();
            let collection = row
                .get("collection")
                .and_then(|value| value.as_str())
                .ok_or_else(|| Error("collection tag count row is missing collection".to_string()))
                .and_then(|value| match value {
                    "functions" => Ok(Collection::Function),
                    "blocks" => Ok(Collection::Block),
                    "instructions" => Ok(Collection::Instruction),
                    _ => Err(Error(format!(
                        "collection tag count row has invalid collection {}",
                        value
                    ))),
                })?;
            let address = row
                .get("address")
                .and_then(|value| value.as_i64())
                .ok_or_else(|| Error("collection tag count row is missing address".to_string()))?
                .max(0) as u64;
            let count = row
                .get("count")
                .and_then(|value| value.as_i64())
                .ok_or_else(|| Error("collection tag count row is missing count".to_string()))?
                .max(0) as usize;
            counts.insert((sha256, collection, address), count);
        }
        Ok(counts)
    }

    pub fn collection_tag_search(
        &self,
        query: &str,
        collection: Option<Collection>,
        page: usize,
        page_size: usize,
    ) -> Result<Page<CollectionTagRecord>, Error> {
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
                "SELECT sha256, collection, address, tag, username, timestamp
             FROM collection_tags
                 WHERE LOWER(tag) LIKE ?1 AND collection = ?2
                 ORDER BY tag ASC, sha256 ASC, address ASC
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
                "SELECT sha256, collection, address, tag, timestamp
                 FROM collection_tags
                 WHERE LOWER(tag) LIKE ?1
                 ORDER BY tag ASC, collection ASC, sha256 ASC, address ASC
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
            .map(|row| -> Result<CollectionTagRecord, Error> {
                let collection = row
                    .get("collection")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| Error("collection tag row is missing collection".to_string()))
                    .and_then(parse_collection)?;
                Ok(CollectionTagRecord {
                    sha256: row
                        .get("sha256")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| Error("collection tag row is missing sha256".to_string()))?
                        .to_string(),
                    collection,
                    address: row
                        .get("address")
                        .and_then(|value| value.as_u64())
                        .ok_or_else(|| {
                            Error("collection tag row is missing address".to_string())
                        })?,
                    tag: row
                        .get("tag")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| Error("collection tag row is missing tag".to_string()))?
                        .to_string(),
                    username: row
                        .get("username")
                        .and_then(|value| value.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    timestamp: row
                        .get("timestamp")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| {
                            Error("collection tag row is missing timestamp".to_string())
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

    pub fn symbol_add(
        &self,
        symbol: &str,
        timestamp: Option<&str>,
        username: Option<&str>,
    ) -> Result<(), Error> {
        let symbol = normalize_metadata_name("symbol", symbol)?;
        let timestamp = timestamp
            .map(ToString::to_string)
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
        let username = username.unwrap_or_default().trim().to_string();
        self.sqlite.execute(
            "INSERT INTO symbols (symbol, username, timestamp)
             VALUES (?1, ?2, ?3)
            ON CONFLICT(symbol) DO UPDATE SET
              username = excluded.username,
              timestamp = excluded.timestamp",
            &[
                SQLiteValue::Text(symbol),
                SQLiteValue::Text(username),
                SQLiteValue::Text(timestamp),
            ],
        )?;
        Ok(())
    }

    pub fn symbol_search(&self, query: &str, limit: usize) -> Result<SymbolSearchPage, Error> {
        let limit = limit.max(1);
        let pattern = if query.trim().is_empty() {
            "%".to_string()
        } else {
            format!("%{}%", query.trim().to_ascii_lowercase())
        };
        let total_rows = self.sqlite.query(
            "SELECT COUNT(*) AS count
             FROM symbols
             WHERE LOWER(symbol) LIKE ?1",
            &[SQLiteValue::Text(pattern.clone())],
        )?;
        let total_results = total_rows
            .into_iter()
            .next()
            .and_then(|row| row.get("count").and_then(|value| value.as_i64()))
            .unwrap_or(0)
            .max(0) as usize;
        let rows = self.sqlite.query(
            "SELECT symbol, username, timestamp
             FROM symbols
             WHERE LOWER(symbol) LIKE ?1
             ORDER BY symbol ASC
             LIMIT ?2",
            &[
                SQLiteValue::Text(pattern),
                SQLiteValue::Integer(limit as i64),
            ],
        )?;
        let items = rows
            .into_iter()
            .map(|row| -> Result<SymbolRecord, Error> {
                Ok(SymbolRecord {
                    symbol: row
                        .get("symbol")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| Error("symbol row is missing symbol".to_string()))?
                        .to_string(),
                    username: row
                        .get("username")
                        .and_then(|value| value.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    timestamp: row
                        .get("timestamp")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| Error("symbol row is missing timestamp".to_string()))?
                        .to_string(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(SymbolSearchPage {
            has_next: total_results > items.len(),
            total_results,
            items,
        })
    }

    pub fn symbol_get(&self, symbol: &str) -> Result<Option<SymbolRecord>, Error> {
        let rows = self.sqlite.query(
            "SELECT symbol, username, timestamp
             FROM symbols
             WHERE symbol = ?1
             LIMIT 1",
            &[SQLiteValue::Text(symbol.trim().to_string())],
        )?;
        rows.into_iter()
            .next()
            .map(|row| {
                Ok(SymbolRecord {
                    symbol: row
                        .get("symbol")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| Error("symbol row is missing symbol".to_string()))?
                        .to_string(),
                    username: row
                        .get("username")
                        .and_then(|value| value.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    timestamp: row
                        .get("timestamp")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| Error("symbol row is missing timestamp".to_string()))?
                        .to_string(),
                })
            })
            .transpose()
    }

    pub fn symbol_delete_global(&self, symbol: &str) -> Result<bool, Error> {
        let symbol = normalize_metadata_name("symbol", symbol)?;
        self.sqlite.execute(
            "DELETE FROM symbols WHERE symbol = ?1",
            &[SQLiteValue::Text(symbol.clone())],
        )?;
        let rows = self.sqlite.query(
            "SELECT symbol FROM symbols WHERE symbol = ?1 LIMIT 1",
            &[SQLiteValue::Text(symbol)],
        )?;
        Ok(rows.is_empty())
    }
}
