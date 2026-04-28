use super::*;

fn normalize_project_tool(value: &str) -> Result<String, Error> {
    match value.trim().to_ascii_lowercase().as_str() {
        "ida" => Ok("ida".to_string()),
        "binja" => Ok("binja".to_string()),
        "ghidra" => Ok("ghidra".to_string()),
        "bundle" => Ok("bundle".to_string()),
        _ => Err(Error(format!("invalid project tool {}", value))),
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_project_tool;

    #[test]
    fn normalize_project_tool_accepts_bundle() {
        assert_eq!(
            normalize_project_tool("bundle").expect("bundle should normalize"),
            "bundle"
        );
    }
}

fn normalize_prefix_filter(value: Option<&str>) -> Option<String> {
    let trimmed = value.unwrap_or_default().trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(format!("{}%", trimmed.to_ascii_lowercase()))
}

fn assignment_sha256(project_sha256: &str, sample_sha256: &str) -> String {
    let digest = digest(
        &SHA256,
        format!("project-assignment:{}:{}", project_sha256, sample_sha256).as_bytes(),
    );
    crate::hex::encode(digest.as_ref())
}

impl LocalDB {
    pub fn project_put(&self, record: &ProjectRecord) -> Result<(), Error> {
        let tool = normalize_project_tool(&record.tool)?;
        let visibility = if record.visibility.trim().is_empty() {
            "public".to_string()
        } else {
            record.visibility.trim().to_ascii_lowercase()
        };
        let timestamp = if record.uploaded_timestamp.trim().is_empty() {
            chrono::Utc::now().to_rfc3339()
        } else {
            record.uploaded_timestamp.clone()
        };
        let updated_timestamp = if record.updated_timestamp.trim().is_empty() {
            timestamp.clone()
        } else {
            record.updated_timestamp.clone()
        };
        self.sqlite.execute(
            "INSERT INTO projects (
                project_sha256,
                tool,
                original_filename,
                storage_key,
                size_bytes,
                content_type,
                container_format,
                visibility,
                uploaded_by,
                uploaded_timestamp,
                updated_timestamp,
                is_deleted
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
             ON CONFLICT(project_sha256) DO UPDATE SET
               tool = excluded.tool,
               original_filename = excluded.original_filename,
               storage_key = excluded.storage_key,
               size_bytes = excluded.size_bytes,
               content_type = excluded.content_type,
               container_format = excluded.container_format,
               visibility = excluded.visibility,
               uploaded_by = excluded.uploaded_by,
               uploaded_timestamp = excluded.uploaded_timestamp,
               updated_timestamp = excluded.updated_timestamp,
               is_deleted = excluded.is_deleted",
            &[
                SQLiteValue::Text(record.project_sha256.clone()),
                SQLiteValue::Text(tool),
                SQLiteValue::Text(record.original_filename.clone()),
                SQLiteValue::Text(record.storage_key.clone()),
                SQLiteValue::Integer(record.size_bytes as i64),
                SQLiteValue::Text(record.content_type.clone()),
                SQLiteValue::Text(record.container_format.clone()),
                SQLiteValue::Text(visibility),
                SQLiteValue::Text(record.uploaded_by.clone()),
                SQLiteValue::Text(timestamp),
                SQLiteValue::Text(updated_timestamp),
                SQLiteValue::Integer(if record.is_deleted { 1 } else { 0 }),
            ],
        )?;
        Ok(())
    }

    pub fn project_get(&self, project_sha256: &str) -> Result<Option<ProjectRecord>, Error> {
        let rows = self.sqlite.query(
            "SELECT
                project_sha256,
                tool,
                original_filename,
                storage_key,
                size_bytes,
                content_type,
                container_format,
                visibility,
                uploaded_by,
                uploaded_timestamp,
                updated_timestamp,
                is_deleted
             FROM projects
             WHERE project_sha256 = ?1
             LIMIT 1",
            &[SQLiteValue::Text(project_sha256.trim().to_string())],
        )?;
        rows.into_iter()
            .next()
            .map(project_record_from_row)
            .transpose()
    }

    pub fn project_search(
        &self,
        params: &ProjectSearchParams,
    ) -> Result<CountedPage<ProjectRecord>, Error> {
        let page = params.page.max(1);
        let page_size = params.page_size.max(1);
        let offset = (page - 1) * page_size;
        let limit = page_size + 1;

        let mut where_sql = String::from(
            " WHERE psa.sample_sha256 = ?1
              AND p.is_deleted = 0",
        );
        let mut query_params = vec![SQLiteValue::Text(params.sample_sha256.clone())];

        if let Some(pattern) = normalize_prefix_filter(params.username.as_deref()) {
            where_sql.push_str(" AND LOWER(p.uploaded_by) LIKE ?");
            query_params.push(SQLiteValue::Text(pattern));
        }
        if let Some(tool) = params
            .tool
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            where_sql.push_str(" AND p.tool = ?");
            query_params.push(SQLiteValue::Text(normalize_project_tool(tool)?));
        }
        if let Some(pattern) = normalize_prefix_filter(params.project_sha256.as_deref()) {
            where_sql.push_str(" AND LOWER(p.project_sha256) LIKE ?");
            query_params.push(SQLiteValue::Text(pattern));
        }

        let count_sql = format!(
            "SELECT COUNT(*) AS count
             FROM project_sample_assignments psa
             INNER JOIN projects p ON p.project_sha256 = psa.project_sha256{}",
            where_sql
        );
        let total_rows = self.sqlite.query(&count_sql, &query_params)?;
        let total_results = total_rows
            .first()
            .and_then(|row| row.get("count"))
            .and_then(|value| value.as_i64())
            .unwrap_or(0)
            .max(0) as usize;

        let mut page_params = query_params.clone();
        page_params.push(SQLiteValue::Integer(limit as i64));
        page_params.push(SQLiteValue::Integer(offset as i64));
        let sql = format!(
            "SELECT
                p.project_sha256,
                p.tool,
                p.original_filename,
                p.storage_key,
                p.size_bytes,
                p.content_type,
                p.container_format,
                p.visibility,
                p.uploaded_by,
                p.uploaded_timestamp,
                p.updated_timestamp,
                p.is_deleted
             FROM project_sample_assignments psa
             INNER JOIN projects p ON p.project_sha256 = psa.project_sha256
             {}
             ORDER BY p.uploaded_timestamp DESC, p.project_sha256 ASC
             LIMIT ? OFFSET ?",
            where_sql
        );
        let rows = self.sqlite.query(&sql, &page_params)?;
        let has_next = rows.len() > page_size;
        let items = rows
            .into_iter()
            .take(page_size)
            .map(project_record_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(CountedPage {
            items,
            page,
            page_size,
            total_results,
            has_next,
        })
    }

    pub fn project_delete(&self, project_sha256: &str) -> Result<(), Error> {
        let timestamp = chrono::Utc::now().to_rfc3339();
        self.sqlite.execute(
            "UPDATE projects
             SET is_deleted = 1, updated_timestamp = ?2
             WHERE project_sha256 = ?1",
            &[
                SQLiteValue::Text(project_sha256.trim().to_string()),
                SQLiteValue::Text(timestamp),
            ],
        )?;
        Ok(())
    }

    pub fn project_assignment_put(
        &self,
        project_sha256: &str,
        sample_sha256: &str,
        sample_state: &str,
        assigned_by: &str,
        timestamp: Option<&str>,
    ) -> Result<ProjectAssignmentRecord, Error> {
        let project_sha256 = project_sha256.trim().to_string();
        let sample_sha256 = sample_sha256.trim().to_string();
        let sample_state = if sample_state.trim().is_empty() {
            "analyzed".to_string()
        } else {
            sample_state.trim().to_ascii_lowercase()
        };
        let timestamp = timestamp
            .map(ToString::to_string)
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
        let record = ProjectAssignmentRecord {
            assignment_sha256: assignment_sha256(&project_sha256, &sample_sha256),
            project_sha256: project_sha256.clone(),
            sample_sha256: sample_sha256.clone(),
            sample_state,
            assigned_by: assigned_by.trim().to_string(),
            assigned_timestamp: timestamp.clone(),
            updated_timestamp: timestamp.clone(),
        };
        self.sqlite.execute(
            "INSERT INTO project_sample_assignments (
                assignment_sha256,
                project_sha256,
                sample_sha256,
                sample_state,
                assigned_by,
                assigned_timestamp,
                updated_timestamp
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(project_sha256, sample_sha256) DO UPDATE SET
               sample_state = excluded.sample_state,
               assigned_by = excluded.assigned_by,
               updated_timestamp = excluded.updated_timestamp",
            &[
                SQLiteValue::Text(record.assignment_sha256.clone()),
                SQLiteValue::Text(record.project_sha256.clone()),
                SQLiteValue::Text(record.sample_sha256.clone()),
                SQLiteValue::Text(record.sample_state.clone()),
                SQLiteValue::Text(record.assigned_by.clone()),
                SQLiteValue::Text(record.assigned_timestamp.clone()),
                SQLiteValue::Text(record.updated_timestamp.clone()),
            ],
        )?;
        Ok(record)
    }

    pub fn project_assignment_delete(
        &self,
        project_sha256: &str,
        sample_sha256: &str,
    ) -> Result<(), Error> {
        self.sqlite.execute(
            "DELETE FROM project_sample_assignments
             WHERE project_sha256 = ?1 AND sample_sha256 = ?2",
            &[
                SQLiteValue::Text(project_sha256.trim().to_string()),
                SQLiteValue::Text(sample_sha256.trim().to_string()),
            ],
        )?;
        Ok(())
    }

    pub fn project_assignment_search(
        &self,
        project_sha256: &str,
        sample_sha256: Option<&str>,
        page: usize,
        page_size: usize,
    ) -> Result<CountedPage<ProjectAssignmentRecord>, Error> {
        let page = page.max(1);
        let page_size = page_size.max(1);
        let offset = (page - 1) * page_size;
        let limit = page_size + 1;
        let mut where_sql = String::from(" WHERE project_sha256 = ?1");
        let mut params = vec![SQLiteValue::Text(project_sha256.trim().to_string())];
        if let Some(pattern) = normalize_prefix_filter(sample_sha256) {
            where_sql.push_str(" AND LOWER(sample_sha256) LIKE ?2");
            params.push(SQLiteValue::Text(pattern));
        }
        let count_sql = format!(
            "SELECT COUNT(*) AS count FROM project_sample_assignments{}",
            where_sql
        );
        let total_rows = self.sqlite.query(&count_sql, &params)?;
        let total_results = total_rows
            .first()
            .and_then(|row| row.get("count"))
            .and_then(|value| value.as_i64())
            .unwrap_or(0)
            .max(0) as usize;
        let mut page_params = params.clone();
        page_params.push(SQLiteValue::Integer(limit as i64));
        page_params.push(SQLiteValue::Integer(offset as i64));
        let sql = format!(
            "SELECT
                assignment_sha256,
                project_sha256,
                sample_sha256,
                sample_state,
                assigned_by,
                assigned_timestamp,
                updated_timestamp
             FROM project_sample_assignments
             {}
             ORDER BY updated_timestamp DESC, sample_sha256 ASC
             LIMIT ? OFFSET ?",
            where_sql
        );
        let rows = self.sqlite.query(&sql, &page_params)?;
        let has_next = rows.len() > page_size;
        let items = rows
            .into_iter()
            .take(page_size)
            .map(project_assignment_record_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(CountedPage {
            items,
            page,
            page_size,
            total_results,
            has_next,
        })
    }

    pub fn sample_project_counts(
        &self,
        sample_sha256s: &[String],
    ) -> Result<BTreeMap<String, usize>, Error> {
        let mut counts = BTreeMap::new();
        if sample_sha256s.is_empty() {
            return Ok(counts);
        }
        let mut sql = String::from(
            "SELECT psa.sample_sha256, COUNT(*) AS count
             FROM project_sample_assignments psa
             INNER JOIN projects p ON p.project_sha256 = psa.project_sha256
             WHERE p.is_deleted = 0
               AND psa.sample_sha256 IN (",
        );
        let mut params = Vec::with_capacity(sample_sha256s.len());
        for (index, sha256) in sample_sha256s.iter().enumerate() {
            if index > 0 {
                sql.push_str(", ");
            }
            sql.push('?');
            params.push(SQLiteValue::Text(sha256.clone()));
        }
        sql.push_str(") GROUP BY psa.sample_sha256");
        let rows = self.sqlite.query(&sql, &params)?;
        for row in rows {
            let Some(sample_sha256) = row
                .get("sample_sha256")
                .and_then(|value| value.as_str())
                .map(ToString::to_string)
            else {
                continue;
            };
            let count = row
                .get("count")
                .and_then(|value| value.as_i64())
                .unwrap_or(0)
                .max(0) as usize;
            counts.insert(sample_sha256, count);
        }
        Ok(counts)
    }
}

fn project_record_from_row(
    row: serde_json::Map<String, serde_json::Value>,
) -> Result<ProjectRecord, Error> {
    Ok(ProjectRecord {
        project_sha256: row
            .get("project_sha256")
            .and_then(|value| value.as_str())
            .ok_or_else(|| Error("project row is missing project_sha256".to_string()))?
            .to_string(),
        tool: row
            .get("tool")
            .and_then(|value| value.as_str())
            .ok_or_else(|| Error("project row is missing tool".to_string()))?
            .to_string(),
        original_filename: row
            .get("original_filename")
            .and_then(|value| value.as_str())
            .ok_or_else(|| Error("project row is missing original_filename".to_string()))?
            .to_string(),
        storage_key: row
            .get("storage_key")
            .and_then(|value| value.as_str())
            .ok_or_else(|| Error("project row is missing storage_key".to_string()))?
            .to_string(),
        size_bytes: row
            .get("size_bytes")
            .and_then(|value| value.as_i64())
            .unwrap_or(0)
            .max(0) as u64,
        content_type: row
            .get("content_type")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string(),
        container_format: row
            .get("container_format")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string(),
        visibility: row
            .get("visibility")
            .and_then(|value| value.as_str())
            .unwrap_or("public")
            .to_string(),
        uploaded_by: row
            .get("uploaded_by")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string(),
        uploaded_timestamp: row
            .get("uploaded_timestamp")
            .and_then(|value| value.as_str())
            .ok_or_else(|| Error("project row is missing uploaded_timestamp".to_string()))?
            .to_string(),
        updated_timestamp: row
            .get("updated_timestamp")
            .and_then(|value| value.as_str())
            .ok_or_else(|| Error("project row is missing updated_timestamp".to_string()))?
            .to_string(),
        is_deleted: row
            .get("is_deleted")
            .and_then(|value| value.as_i64())
            .unwrap_or(0)
            != 0,
    })
}

fn project_assignment_record_from_row(
    row: serde_json::Map<String, serde_json::Value>,
) -> Result<ProjectAssignmentRecord, Error> {
    Ok(ProjectAssignmentRecord {
        assignment_sha256: row
            .get("assignment_sha256")
            .and_then(|value| value.as_str())
            .ok_or_else(|| Error("assignment row is missing assignment_sha256".to_string()))?
            .to_string(),
        project_sha256: row
            .get("project_sha256")
            .and_then(|value| value.as_str())
            .ok_or_else(|| Error("assignment row is missing project_sha256".to_string()))?
            .to_string(),
        sample_sha256: row
            .get("sample_sha256")
            .and_then(|value| value.as_str())
            .ok_or_else(|| Error("assignment row is missing sample_sha256".to_string()))?
            .to_string(),
        sample_state: row
            .get("sample_state")
            .and_then(|value| value.as_str())
            .unwrap_or("analyzed")
            .to_string(),
        assigned_by: row
            .get("assigned_by")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string(),
        assigned_timestamp: row
            .get("assigned_timestamp")
            .and_then(|value| value.as_str())
            .ok_or_else(|| Error("assignment row is missing assigned_timestamp".to_string()))?
            .to_string(),
        updated_timestamp: row
            .get("updated_timestamp")
            .and_then(|value| value.as_str())
            .ok_or_else(|| Error("assignment row is missing updated_timestamp".to_string()))?
            .to_string(),
    })
}
