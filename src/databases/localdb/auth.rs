use super::*;

impl LocalDB {
    pub fn role_create(&self, name: &str, timestamp: Option<&str>) -> Result<RoleRecord, Error> {
        let name = normalize_role_name(name)?;
        let record = RoleRecord {
            name: name.to_string(),
            timestamp: timestamp
                .map(ToString::to_string)
                .unwrap_or_else(|| chrono::Utc::now().to_rfc3339()),
        };
        self.sqlite.execute(
            "INSERT INTO roles (name, timestamp)
             VALUES (?1, ?2)",
            &[
                SQLiteValue::Text(record.name.clone()),
                SQLiteValue::Text(record.timestamp.clone()),
            ],
        )?;
        Ok(record)
    }

    pub fn role_get(&self, name: &str) -> Result<Option<RoleRecord>, Error> {
        let name = normalize_role_name(name)?;
        let rows = self.sqlite.query(
            "SELECT name, timestamp FROM roles WHERE name = ?1 LIMIT 1",
            &[SQLiteValue::Text(name.to_string())],
        )?;
        Ok(rows.into_iter().next().map(|row| RoleRecord {
            name: row
                .get("name")
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_string(),
            timestamp: row
                .get("timestamp")
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_string(),
        }))
    }

    pub fn role_search(
        &self,
        query: &str,
        page: usize,
        limit: usize,
    ) -> Result<Page<RoleRecord>, Error> {
        let page = page.max(1);
        let limit = limit.max(1);
        let offset = (page - 1) * limit;
        let like = format!("%{}%", query.trim().to_ascii_lowercase());
        let rows = self.sqlite.query(
            "SELECT name, timestamp
             FROM roles
             WHERE lower(name) LIKE ?1
             ORDER BY name ASC
             LIMIT ?2 OFFSET ?3",
            &[
                SQLiteValue::Text(like),
                SQLiteValue::Integer((limit + 1) as i64),
                SQLiteValue::Integer(offset as i64),
            ],
        )?;
        let has_next = rows.len() > limit;
        let items = rows
            .into_iter()
            .take(limit)
            .map(|row| RoleRecord {
                name: row
                    .get("name")
                    .and_then(|value| value.as_str())
                    .unwrap_or_default()
                    .to_string(),
                timestamp: row
                    .get("timestamp")
                    .and_then(|value| value.as_str())
                    .unwrap_or_default()
                    .to_string(),
            })
            .collect();
        Ok(Page {
            items,
            page,
            page_size: limit,
            has_next,
        })
    }

    pub fn role_delete(&self, name: &str) -> Result<bool, Error> {
        let name = normalize_role_name(name)?;
        if is_reserved_role(name) {
            return Err(Error(format!("role {} is reserved", name)));
        }
        if self.role_get(name)?.is_none() {
            return Ok(false);
        }
        let in_use = self.sqlite.query(
            "SELECT username FROM users WHERE role = ?1 LIMIT 1",
            &[SQLiteValue::Text(name.to_string())],
        )?;
        if !in_use.is_empty() {
            return Err(Error(format!("role {} is still in use", name)));
        }
        self.sqlite.execute(
            "DELETE FROM roles WHERE name = ?1",
            &[SQLiteValue::Text(name.to_string())],
        )?;
        let rows = self.sqlite.query(
            "SELECT name FROM roles WHERE name = ?1",
            &[SQLiteValue::Text(name.to_string())],
        )?;
        Ok(rows.is_empty())
    }

    pub fn user_create(
        &self,
        username: &str,
        role: &str,
        timestamp: Option<&str>,
    ) -> Result<(UserRecord, String, Vec<String>), Error> {
        self.user_create_account(
            username,
            &generate_password_secret(),
            role,
            false,
            false,
            timestamp,
        )
    }

    pub fn user_create_account(
        &self,
        username: &str,
        password: &str,
        role: &str,
        reserved: bool,
        two_factor_required: bool,
        timestamp: Option<&str>,
    ) -> Result<(UserRecord, String, Vec<String>), Error> {
        let username = normalize_username(username)?;
        let role = normalize_role_name(role)?;
        normalize_password(password)?;
        if self.role_get(role)?.is_none() {
            return Err(Error(format!("role {} does not exist", role)));
        }
        if self.user_get(&username)?.is_some() {
            return Err(Error(format!("user {} already exists", username)));
        }
        let api_key = generate_api_key();
        let recovery_codes = generate_recovery_codes();
        let when = timestamp
            .map(ToString::to_string)
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
        let record = UserRecord {
            username: username.to_string(),
            api_key: api_key.clone(),
            role: role.to_string(),
            enabled: true,
            reserved,
            profile_picture: None,
            two_factor_enabled: false,
            two_factor_required,
            timestamp: when.clone(),
        };
        self.sqlite.execute(
            "INSERT INTO users (username, email, password_hash, role, api_key, enabled, reserved, profile_picture, two_factor_enabled, two_factor_required, two_factor_secret, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            &[
                SQLiteValue::Text(record.username.clone()),
                SQLiteValue::Text(String::new()),
                SQLiteValue::Text(hash_password(password)?),
                SQLiteValue::Text(record.role.clone()),
                SQLiteValue::Text(record.api_key.clone()),
                SQLiteValue::Integer(if record.enabled { 1 } else { 0 }),
                SQLiteValue::Integer(if record.reserved { 1 } else { 0 }),
                match &record.profile_picture {
                    Some(value) => SQLiteValue::Text(value.clone()),
                    None => SQLiteValue::Null,
                },
                SQLiteValue::Integer(if record.two_factor_enabled { 1 } else { 0 }),
                SQLiteValue::Integer(if record.two_factor_required { 1 } else { 0 }),
                SQLiteValue::Null,
                SQLiteValue::Text(record.timestamp.clone()),
            ],
        )?;
        self.replace_recovery_codes(&record.username, &recovery_codes, &when)?;
        Ok((record, api_key, recovery_codes))
    }

    pub fn user_count(&self) -> Result<usize, Error> {
        let rows = self
            .sqlite
            .query("SELECT COUNT(*) AS count FROM users", &[])?;
        Ok(rows
            .into_iter()
            .next()
            .and_then(|row| row.get("count").and_then(|value| value.as_i64()))
            .unwrap_or(0) as usize)
    }

    pub fn username_availability(&self, username: &str) -> Result<(String, bool), Error> {
        let normalized = normalize_username(username)?;
        let available = self.user_get(&normalized)?.is_none();
        Ok((normalized, available))
    }

    pub fn admin_count(&self) -> Result<usize, Error> {
        let rows = self.sqlite.query(
            "SELECT COUNT(*) AS count FROM users WHERE role = 'admin'",
            &[],
        )?;
        Ok(rows
            .into_iter()
            .next()
            .and_then(|row| row.get("count").and_then(|value| value.as_i64()))
            .unwrap_or(0) as usize)
    }

    pub fn enabled_admin_count(&self) -> Result<usize, Error> {
        let rows = self.sqlite.query(
            "SELECT COUNT(*) AS count FROM users WHERE role = 'admin' AND enabled = 1",
            &[],
        )?;
        Ok(rows
            .into_iter()
            .next()
            .and_then(|row| row.get("count").and_then(|value| value.as_i64()))
            .unwrap_or(0) as usize)
    }

    pub fn user_authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<UserRecord>, Error> {
        let username = normalize_username(username)?;
        if username.is_empty() {
            return Ok(None);
        }
        let rows = self.sqlite.query(
            "SELECT username, email, api_key, role, enabled, reserved, profile_picture, two_factor_enabled, two_factor_required, two_factor_secret, password_hash, timestamp
             FROM users
             WHERE lower(username) = ?1 AND enabled = 1
             LIMIT 1",
            &[SQLiteValue::Text(username)],
        )?;
        let Some(row) = rows.into_iter().next() else {
            return Ok(None);
        };
        let password_hash = row
            .get("password_hash")
            .and_then(|value| value.as_str())
            .ok_or_else(|| Error("user row is missing password_hash".to_string()))?;
        if !verify_password(password_hash, password)? {
            return Ok(None);
        }
        Ok(Some(user_record_from_row(row)?))
    }

    pub fn user_update_role(&self, username: &str, role: &str) -> Result<UserRecord, Error> {
        let username = normalize_username(username)?;
        let role = normalize_role_name(role)?;
        let current = self
            .user_get(&username)?
            .ok_or_else(|| Error(format!("user {} does not exist", username)))?;
        if current.reserved {
            return Err(Error(format!("user {} is reserved", username)));
        }
        if current.role == "admin"
            && current.enabled
            && role != "admin"
            && self.enabled_admin_count()? <= 1
        {
            return Err(Error("cannot remove the last admin role".to_string()));
        }
        self.sqlite.execute(
            "UPDATE users SET role = ?1, timestamp = ?2 WHERE username = ?3",
            &[
                SQLiteValue::Text(role.to_string()),
                SQLiteValue::Text(chrono::Utc::now().to_rfc3339()),
                SQLiteValue::Text(username.to_string()),
            ],
        )?;
        self.user_get(&username)?
            .ok_or_else(|| Error(format!("user {} does not exist", username)))
    }

    pub fn user_update_profile_picture(
        &self,
        username: &str,
        profile_picture: Option<&str>,
    ) -> Result<UserRecord, Error> {
        let username = normalize_username(username)?;
        let current = self
            .user_get(&username)?
            .ok_or_else(|| Error(format!("user {} does not exist", username)))?;
        if current.reserved {
            return Err(Error(format!("user {} is reserved", username)));
        }
        self.sqlite.execute(
            "UPDATE users SET profile_picture = ?1, timestamp = ?2 WHERE username = ?3",
            &[
                match profile_picture
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                {
                    Some(value) => SQLiteValue::Text(value.to_string()),
                    None => SQLiteValue::Null,
                },
                SQLiteValue::Text(chrono::Utc::now().to_rfc3339()),
                SQLiteValue::Text(username.to_string()),
            ],
        )?;
        self.user_get(&username)?
            .ok_or_else(|| Error(format!("user {} does not exist", username)))
    }

    pub fn user_begin_two_factor_setup(
        &self,
        username: &str,
        secret: &str,
    ) -> Result<UserRecord, Error> {
        let username = normalize_username(username)?;
        let current = self
            .user_get(&username)?
            .ok_or_else(|| Error(format!("user {} does not exist", username)))?;
        if !current.enabled {
            return Err(Error(format!("user {} is disabled", username)));
        }
        self.sqlite.execute(
            "UPDATE users
             SET two_factor_secret = ?1,
                 two_factor_enabled = 0,
                 timestamp = ?2
             WHERE username = ?3",
            &[
                SQLiteValue::Text(secret.trim().to_string()),
                SQLiteValue::Text(chrono::Utc::now().to_rfc3339()),
                SQLiteValue::Text(username.to_string()),
            ],
        )?;
        self.user_get(&username)?
            .ok_or_else(|| Error(format!("user {} does not exist", username)))
    }

    pub fn user_enable_two_factor(
        &self,
        username: &str,
        timestamp: Option<&str>,
    ) -> Result<UserRecord, Error> {
        let username = normalize_username(username)?;
        let current = self
            .user_get(&username)?
            .ok_or_else(|| Error(format!("user {} does not exist", username)))?;
        if !current.enabled {
            return Err(Error(format!("user {} is disabled", username)));
        }
        let rows = self.sqlite.query(
            "SELECT two_factor_secret FROM users WHERE username = ?1 LIMIT 1",
            &[SQLiteValue::Text(username.to_string())],
        )?;
        let Some(row) = rows.into_iter().next() else {
            return Err(Error(format!("user {} does not exist", username)));
        };
        let secret = row
            .get("two_factor_secret")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .trim()
            .to_string();
        if secret.is_empty() {
            return Err(Error("two-factor setup has not been started".to_string()));
        }
        let when = timestamp
            .map(ToString::to_string)
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
        self.sqlite.execute(
            "UPDATE users
             SET two_factor_enabled = 1,
                 timestamp = ?1
             WHERE username = ?2",
            &[
                SQLiteValue::Text(when),
                SQLiteValue::Text(username.to_string()),
            ],
        )?;
        self.user_get(&username)?
            .ok_or_else(|| Error(format!("user {} does not exist", username)))
    }

    pub fn user_two_factor_secret(&self, username: &str) -> Result<Option<String>, Error> {
        let username = normalize_username(username)?;
        let rows = self.sqlite.query(
            "SELECT two_factor_secret FROM users WHERE username = ?1 LIMIT 1",
            &[SQLiteValue::Text(username.to_string())],
        )?;
        Ok(rows
            .into_iter()
            .next()
            .and_then(|row| {
                row.get("two_factor_secret")
                    .and_then(|value| value.as_str())
                    .map(ToString::to_string)
            })
            .filter(|value| !value.trim().is_empty()))
    }

    pub fn user_disable_two_factor(
        &self,
        username: &str,
        clear_required: bool,
        timestamp: Option<&str>,
    ) -> Result<UserRecord, Error> {
        let username = normalize_username(username)?;
        let current = self
            .user_get(&username)?
            .ok_or_else(|| Error(format!("user {} does not exist", username)))?;
        if current.reserved {
            return Err(Error(format!("user {} is reserved", username)));
        }
        let when = timestamp
            .map(ToString::to_string)
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
        self.sqlite.execute(
            "UPDATE users
             SET two_factor_secret = NULL,
                 two_factor_enabled = 0,
                 two_factor_required = ?1,
                 timestamp = ?2
             WHERE username = ?3",
            &[
                SQLiteValue::Integer(if clear_required { 0 } else { 1 }),
                SQLiteValue::Text(when),
                SQLiteValue::Text(username.to_string()),
            ],
        )?;
        self.user_get(&username)?
            .ok_or_else(|| Error(format!("user {} does not exist", username)))
    }

    pub fn user_require_two_factor(
        &self,
        username: &str,
        required: bool,
        timestamp: Option<&str>,
    ) -> Result<UserRecord, Error> {
        let username = normalize_username(username)?;
        let current = self
            .user_get(&username)?
            .ok_or_else(|| Error(format!("user {} does not exist", username)))?;
        if current.reserved {
            return Err(Error(format!("user {} is reserved", username)));
        }
        let when = timestamp
            .map(ToString::to_string)
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
        self.sqlite.execute(
            "UPDATE users SET two_factor_required = ?1, timestamp = ?2 WHERE username = ?3",
            &[
                SQLiteValue::Integer(if required { 1 } else { 0 }),
                SQLiteValue::Text(when),
                SQLiteValue::Text(username.to_string()),
            ],
        )?;
        self.user_get(&username)?
            .ok_or_else(|| Error(format!("user {} does not exist", username)))
    }

    pub fn user_change_password(
        &self,
        username: &str,
        current_password: &str,
        new_password: &str,
    ) -> Result<(), Error> {
        let username = normalize_username(username)?;
        normalize_password(new_password)?;
        let rows = self.sqlite.query(
            "SELECT password_hash FROM users WHERE username = ?1 LIMIT 1",
            &[SQLiteValue::Text(username.to_string())],
        )?;
        let Some(row) = rows.into_iter().next() else {
            return Err(Error(format!("user {} does not exist", username)));
        };
        let password_hash = row
            .get("password_hash")
            .and_then(|value| value.as_str())
            .ok_or_else(|| Error("user row is missing password_hash".to_string()))?;
        if !verify_password(password_hash, current_password)? {
            return Err(Error("current password is invalid".to_string()));
        }
        self.user_set_password(&username, new_password)
    }

    pub fn user_set_password(&self, username: &str, password: &str) -> Result<(), Error> {
        let username = normalize_username(username)?;
        normalize_password(password)?;
        self.sqlite.execute(
            "UPDATE users SET password_hash = ?1, timestamp = ?2 WHERE username = ?3",
            &[
                SQLiteValue::Text(hash_password(password)?),
                SQLiteValue::Text(chrono::Utc::now().to_rfc3339()),
                SQLiteValue::Text(username.to_string()),
            ],
        )?;
        Ok(())
    }

    pub fn user_regenerate_recovery_codes(
        &self,
        username: &str,
        timestamp: Option<&str>,
    ) -> Result<Vec<String>, Error> {
        let username = normalize_username(username)?;
        let current = self
            .user_get(&username)?
            .ok_or_else(|| Error(format!("user {} does not exist", username)))?;
        if current.reserved {
            return Err(Error(format!("user {} is reserved", username)));
        }
        let codes = generate_recovery_codes();
        let when = timestamp
            .map(ToString::to_string)
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
        self.replace_recovery_codes(&username, &codes, &when)?;
        Ok(codes)
    }

    pub fn user_reset_with_recovery_code(
        &self,
        username: &str,
        recovery_code: &str,
        new_password: &str,
        timestamp: Option<&str>,
    ) -> Result<(), Error> {
        let username = normalize_username(username)?;
        normalize_password(new_password)?;
        let current = self
            .user_get(&username)?
            .ok_or_else(|| Error(format!("user {} does not exist", username)))?;
        if !current.enabled {
            return Err(Error(format!("user {} is disabled", username)));
        }
        let _when = self.consume_recovery_code(&username, recovery_code, timestamp)?;
        self.user_set_password(&username, new_password)?;
        Ok(())
    }

    pub fn user_consume_recovery_code(
        &self,
        username: &str,
        recovery_code: &str,
        timestamp: Option<&str>,
    ) -> Result<(), Error> {
        let username = normalize_username(username)?;
        let _ = self.consume_recovery_code(&username, recovery_code, timestamp)?;
        Ok(())
    }

    pub fn user_delete(&self, username: &str) -> Result<bool, Error> {
        let username = normalize_username(username)?;
        let current = self
            .user_get(&username)?
            .ok_or_else(|| Error(format!("user {} does not exist", username)))?;
        if current.reserved {
            return Err(Error(format!("user {} is reserved", username)));
        }
        if current.role == "admin" && current.enabled && self.enabled_admin_count()? <= 1 {
            return Err(Error("cannot delete the last admin".to_string()));
        }
        self.sqlite.execute(
            "DELETE FROM sessions WHERE username = ?1",
            &[SQLiteValue::Text(username.to_string())],
        )?;
        self.sqlite.execute(
            "DELETE FROM login_challenges WHERE username = ?1",
            &[SQLiteValue::Text(username.to_string())],
        )?;
        self.sqlite.execute(
            "DELETE FROM recovery_codes WHERE username = ?1",
            &[SQLiteValue::Text(username.to_string())],
        )?;
        self.sqlite.execute(
            "DELETE FROM users WHERE username = ?1",
            &[SQLiteValue::Text(username.to_string())],
        )?;
        Ok(self.user_get(&username)?.is_none())
    }

    pub fn user_regenerate_key(
        &self,
        username: &str,
        timestamp: Option<&str>,
    ) -> Result<String, Error> {
        let username = normalize_username(username)?;
        let current = self
            .user_get(&username)?
            .ok_or_else(|| Error(format!("user {} does not exist", username)))?;
        if current.reserved {
            return Err(Error(format!("user {} is reserved", username)));
        }
        let plaintext = generate_api_key();
        let when = timestamp
            .map(ToString::to_string)
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
        self.sqlite.execute(
            "UPDATE users SET api_key = ?1, timestamp = ?2 WHERE username = ?3",
            &[
                SQLiteValue::Text(plaintext.clone()),
                SQLiteValue::Text(when),
                SQLiteValue::Text(username.to_string()),
            ],
        )?;
        Ok(plaintext)
    }

    pub fn user_disable(&self, username: &str) -> Result<bool, Error> {
        let username = normalize_username(username)?;
        let current = self
            .user_get(&username)?
            .ok_or_else(|| Error(format!("user {} does not exist", username)))?;
        if current.reserved {
            return Err(Error(format!("user {} is reserved", username)));
        }
        if current.role == "admin" && current.enabled && self.enabled_admin_count()? <= 1 {
            return Err(Error("cannot disable the last enabled admin".to_string()));
        }
        self.sqlite.execute(
            "UPDATE users SET enabled = 0, timestamp = ?1 WHERE username = ?2",
            &[
                SQLiteValue::Text(chrono::Utc::now().to_rfc3339()),
                SQLiteValue::Text(username.to_string()),
            ],
        )?;
        self.sqlite.execute(
            "UPDATE sessions SET enabled = 0 WHERE username = ?1",
            &[SQLiteValue::Text(username.to_string())],
        )?;
        self.sqlite.execute(
            "UPDATE login_challenges SET enabled = 0 WHERE username = ?1",
            &[SQLiteValue::Text(username.to_string())],
        )?;
        Ok(true)
    }

    pub fn user_enable(&self, username: &str) -> Result<bool, Error> {
        let username = normalize_username(username)?;
        let current = self
            .user_get(&username)?
            .ok_or_else(|| Error(format!("user {} does not exist", username)))?;
        if current.reserved {
            return Err(Error(format!("user {} is reserved", username)));
        }
        self.sqlite.execute(
            "UPDATE users SET enabled = 1, timestamp = ?1 WHERE username = ?2",
            &[
                SQLiteValue::Text(chrono::Utc::now().to_rfc3339()),
                SQLiteValue::Text(username.to_string()),
            ],
        )?;
        Ok(self.user_get(&username)?.is_some())
    }

    pub fn user_reset(&self, username: &str, timestamp: Option<&str>) -> Result<String, Error> {
        let password = generate_password_secret();
        self.user_set_password(username, &password)?;
        if let Some(when) = timestamp {
            self.sqlite.execute(
                "UPDATE users SET timestamp = ?1 WHERE username = ?2",
                &[
                    SQLiteValue::Text(when.to_string()),
                    SQLiteValue::Text(normalize_username(username)?.to_string()),
                ],
            )?;
        }
        Ok(password)
    }

    pub fn user_get(&self, username: &str) -> Result<Option<UserRecord>, Error> {
        let username = normalize_username(username)?;
        let rows = self.sqlite.query(
            "SELECT username, email, api_key, role, enabled, reserved, profile_picture, two_factor_enabled, two_factor_required, two_factor_secret, timestamp
             FROM users
             WHERE username = ?1
             LIMIT 1",
            &[SQLiteValue::Text(username.to_string())],
        )?;
        Ok(rows
            .into_iter()
            .next()
            .map(user_record_from_row)
            .transpose()?)
    }

    pub fn user_search(
        &self,
        query: &str,
        page: usize,
        limit: usize,
    ) -> Result<Page<UserRecord>, Error> {
        let page = page.max(1);
        let limit = limit.max(1);
        let offset = (page - 1) * limit;
        let like = format!("%{}%", query.trim().to_ascii_lowercase());
        let rows = self.sqlite.query(
            "SELECT username, email, api_key, role, enabled, reserved, profile_picture, two_factor_enabled, two_factor_required, two_factor_secret, timestamp
             FROM users
             WHERE lower(username) LIKE ?1 OR lower(role) LIKE ?1
             ORDER BY reserved DESC, username ASC
             LIMIT ?2 OFFSET ?3",
            &[
                SQLiteValue::Text(like),
                SQLiteValue::Integer((limit + 1) as i64),
                SQLiteValue::Integer(offset as i64),
            ],
        )?;
        let has_next = rows.len() > limit;
        let items = rows
            .into_iter()
            .take(limit)
            .map(user_record_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Page {
            items,
            page,
            page_size: limit,
            has_next,
        })
    }

    pub fn user_search_total(&self, query: &str) -> Result<usize, Error> {
        let like = format!("%{}%", query.trim().to_ascii_lowercase());
        let rows = self.sqlite.query(
            "SELECT COUNT(*) AS count
             FROM users
             WHERE lower(username) LIKE ?1 OR lower(role) LIKE ?1",
            &[SQLiteValue::Text(like)],
        )?;
        Ok(rows
            .into_iter()
            .next()
            .and_then(|row| row.get("count").and_then(|value| value.as_i64()))
            .unwrap_or(0) as usize)
    }

    pub fn auth_check(&self, api_key: &str) -> Result<bool, Error> {
        Ok(self.auth_user(api_key)?.is_some())
    }

    pub fn auth_user(&self, api_key: &str) -> Result<Option<UserRecord>, Error> {
        let api_key = api_key.trim();
        if api_key.is_empty() {
            return Ok(None);
        }
        let rows = self.sqlite.query(
            "SELECT username, email, api_key, role, enabled, reserved, profile_picture, two_factor_enabled, two_factor_required, two_factor_secret, timestamp
             FROM users
             WHERE api_key = ?1 AND enabled = 1
             LIMIT 1",
            &[SQLiteValue::Text(api_key.to_string())],
        )?;
        Ok(rows
            .into_iter()
            .next()
            .map(user_record_from_row)
            .transpose()?)
    }

    pub fn session_create(
        &self,
        username: &str,
        ttl_seconds: u64,
    ) -> Result<(SessionRecord, String), Error> {
        let username = normalize_username(username)?;
        let current = self
            .user_get(&username)?
            .ok_or_else(|| Error(format!("user {} does not exist", username)))?;
        if !current.enabled {
            return Err(Error(format!("user {} is disabled", username)));
        }
        let plaintext = generate_secret();
        let now = chrono::Utc::now();
        let expires = now
            .checked_add_signed(chrono::TimeDelta::seconds(ttl_seconds as i64))
            .ok_or_else(|| Error("failed to compute session expiry".to_string()))?;
        let record = SessionRecord {
            id: generate_session_id(),
            username: username.to_string(),
            enabled: true,
            timestamp: now.to_rfc3339(),
            expires: expires.to_rfc3339(),
        };
        self.sqlite.execute(
            "INSERT INTO sessions (id, session, username, enabled, timestamp, expires)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            &[
                SQLiteValue::Text(record.id.clone()),
                SQLiteValue::Text(hash_secret(&plaintext)),
                SQLiteValue::Text(record.username.clone()),
                SQLiteValue::Integer(if record.enabled { 1 } else { 0 }),
                SQLiteValue::Text(record.timestamp.clone()),
                SQLiteValue::Text(record.expires.clone()),
            ],
        )?;
        Ok((record, plaintext))
    }

    pub fn session_user(&self, session: &str) -> Result<Option<UserRecord>, Error> {
        let session = session.trim();
        if session.is_empty() {
            return Ok(None);
        }
        let rows = self.sqlite.query(
            "SELECT users.username, users.email, users.api_key, users.role, users.enabled, users.reserved, users.profile_picture, users.two_factor_enabled, users.two_factor_required, users.two_factor_secret, users.timestamp, sessions.expires, sessions.enabled AS session_enabled
             FROM sessions
             JOIN users ON users.username = sessions.username
             WHERE sessions.session = ?1
             LIMIT 1",
            &[SQLiteValue::Text(hash_secret(session))],
        )?;
        let Some(row) = rows.into_iter().next() else {
            return Ok(None);
        };
        let session_enabled = row
            .get("session_enabled")
            .and_then(|value| value.as_i64())
            .map(|value| value != 0)
            .ok_or_else(|| Error("session row is missing enabled".to_string()))?;
        if !session_enabled {
            return Ok(None);
        }
        let user_enabled = row
            .get("enabled")
            .and_then(|value| value.as_i64())
            .map(|value| value != 0)
            .ok_or_else(|| Error("user row is missing enabled".to_string()))?;
        if !user_enabled {
            return Ok(None);
        }
        let expires = row
            .get("expires")
            .and_then(|value| value.as_str())
            .ok_or_else(|| Error("session row is missing expires".to_string()))?;
        let expires = chrono::DateTime::parse_from_rfc3339(expires)
            .map_err(|error| Error(format!("invalid session expiry {}: {}", expires, error)))?
            .with_timezone(&chrono::Utc);
        if chrono::Utc::now() >= expires {
            return Ok(None);
        }
        Ok(Some(user_record_from_row(row)?))
    }

    pub fn login_challenge_create(
        &self,
        username: &str,
        setup_required: bool,
        ttl_seconds: u64,
    ) -> Result<(LoginChallengeRecord, String), Error> {
        let username = normalize_username(username)?;
        let current = self
            .user_get(&username)?
            .ok_or_else(|| Error(format!("user {} does not exist", username)))?;
        if !current.enabled {
            return Err(Error(format!("user {} is disabled", username)));
        }
        let plaintext = generate_secret();
        let now = chrono::Utc::now();
        let expires = now
            .checked_add_signed(chrono::TimeDelta::seconds(ttl_seconds as i64))
            .ok_or_else(|| Error("failed to compute login challenge expiry".to_string()))?;
        let record = LoginChallengeRecord {
            id: generate_login_challenge_id(),
            username: username.to_string(),
            setup_required,
            enabled: true,
            timestamp: now.to_rfc3339(),
            expires: expires.to_rfc3339(),
        };
        self.sqlite.execute(
            "INSERT INTO login_challenges (id, challenge, username, setup_required, enabled, timestamp, expires)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            &[
                SQLiteValue::Text(record.id.clone()),
                SQLiteValue::Text(hash_secret(&plaintext)),
                SQLiteValue::Text(record.username.clone()),
                SQLiteValue::Integer(if record.setup_required { 1 } else { 0 }),
                SQLiteValue::Integer(if record.enabled { 1 } else { 0 }),
                SQLiteValue::Text(record.timestamp.clone()),
                SQLiteValue::Text(record.expires.clone()),
            ],
        )?;
        Ok((record, plaintext))
    }

    pub fn login_challenge_user(
        &self,
        challenge: &str,
    ) -> Result<Option<(UserRecord, LoginChallengeRecord)>, Error> {
        let challenge = challenge.trim();
        if challenge.is_empty() {
            return Ok(None);
        }
        let rows = self.sqlite.query(
            "SELECT users.username, users.email, users.api_key, users.role, users.enabled, users.reserved,
                    users.profile_picture, users.two_factor_enabled, users.two_factor_required, users.two_factor_secret,
                    users.timestamp,
                    login_challenges.id AS challenge_id,
                    login_challenges.setup_required,
                    login_challenges.enabled AS challenge_enabled,
                    login_challenges.timestamp AS challenge_timestamp,
                    login_challenges.expires
             FROM login_challenges
             JOIN users ON users.username = login_challenges.username
             WHERE login_challenges.challenge = ?1
             LIMIT 1",
            &[SQLiteValue::Text(hash_secret(challenge))],
        )?;
        let Some(row) = rows.into_iter().next() else {
            return Ok(None);
        };
        let enabled = row
            .get("challenge_enabled")
            .and_then(|value| value.as_i64())
            .map(|value| value != 0)
            .ok_or_else(|| Error("login challenge row is missing enabled".to_string()))?;
        if !enabled {
            return Ok(None);
        }
        let expires = row
            .get("expires")
            .and_then(|value| value.as_str())
            .ok_or_else(|| Error("login challenge row is missing expires".to_string()))?
            .to_string();
        let expiry = chrono::DateTime::parse_from_rfc3339(&expires)
            .map_err(|error| Error(error.to_string()))?
            .with_timezone(&chrono::Utc);
        if expiry < chrono::Utc::now() {
            return Ok(None);
        }
        let record = LoginChallengeRecord {
            id: row
                .get("challenge_id")
                .and_then(|value| value.as_str())
                .ok_or_else(|| Error("login challenge row is missing id".to_string()))?
                .to_string(),
            username: row
                .get("username")
                .and_then(|value| value.as_str())
                .ok_or_else(|| Error("login challenge row is missing username".to_string()))?
                .to_string(),
            setup_required: row
                .get("setup_required")
                .and_then(|value| value.as_i64())
                .map(|value| value != 0)
                .unwrap_or(false),
            enabled,
            timestamp: row
                .get("challenge_timestamp")
                .and_then(|value| value.as_str())
                .ok_or_else(|| Error("login challenge row is missing timestamp".to_string()))?
                .to_string(),
            expires,
        };
        Ok(Some((user_record_from_row(row)?, record)))
    }

    pub fn login_challenge_disable_value(&self, challenge: &str) -> Result<bool, Error> {
        let challenge = challenge.trim();
        if challenge.is_empty() {
            return Ok(false);
        }
        self.sqlite.execute(
            "UPDATE login_challenges SET enabled = 0 WHERE challenge = ?1",
            &[SQLiteValue::Text(hash_secret(challenge))],
        )?;
        Ok(true)
    }

    pub fn session_disable_value(&self, session: &str) -> Result<bool, Error> {
        let session = session.trim();
        if session.is_empty() {
            return Err(Error("session must not be empty".to_string()));
        }
        self.sqlite.execute(
            "UPDATE sessions SET enabled = 0 WHERE session = ?1",
            &[SQLiteValue::Text(hash_secret(session))],
        )?;
        let rows = self.sqlite.query(
            "SELECT enabled FROM sessions WHERE session = ?1",
            &[SQLiteValue::Text(hash_secret(session))],
        )?;
        Ok(!rows.is_empty())
    }

    pub fn session_clear(&self) -> Result<usize, Error> {
        let now = chrono::Utc::now().to_rfc3339();
        let before = self.sqlite.query(
            "SELECT id FROM sessions WHERE expires <= ?1",
            &[SQLiteValue::Text(now.clone())],
        )?;
        self.sqlite.execute(
            "DELETE FROM sessions WHERE expires <= ?1",
            &[SQLiteValue::Text(now)],
        )?;
        Ok(before.len())
    }

    pub fn captcha_create(
        &self,
        answer: &str,
        ttl_seconds: u64,
    ) -> Result<(CaptchaRecord, String), Error> {
        let answer = answer.trim().to_ascii_lowercase();
        if answer.is_empty() {
            return Err(Error("captcha answer must not be empty".to_string()));
        }
        let now = chrono::Utc::now();
        let expires = now
            .checked_add_signed(chrono::TimeDelta::seconds(ttl_seconds as i64))
            .ok_or_else(|| Error("failed to compute captcha expiry".to_string()))?;
        let record = CaptchaRecord {
            id: generate_captcha_id(),
            answer_hash: hash_secret(&answer),
            used: false,
            timestamp: now.to_rfc3339(),
            expires: expires.to_rfc3339(),
        };
        self.sqlite.execute(
            "INSERT INTO captchas (id, answer_hash, used, timestamp, expires)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &[
                SQLiteValue::Text(record.id.clone()),
                SQLiteValue::Text(record.answer_hash.clone()),
                SQLiteValue::Integer(0),
                SQLiteValue::Text(record.timestamp.clone()),
                SQLiteValue::Text(record.expires.clone()),
            ],
        )?;
        Ok((record, answer))
    }

    pub fn captcha_verify_once(&self, id: &str, answer: &str) -> Result<(), Error> {
        let id = id.trim();
        let answer = answer.trim().to_ascii_lowercase();
        if id.is_empty() || answer.is_empty() {
            return Err(Error("captcha is required".to_string()));
        }
        let rows = self.sqlite.query(
            "SELECT used, expires
             FROM captchas
             WHERE id = ?1
             LIMIT 1",
            &[SQLiteValue::Text(id.to_string())],
        )?;
        let Some(row) = rows.into_iter().next() else {
            return Err(Error("captcha challenge is invalid".to_string()));
        };
        let used = row
            .get("used")
            .and_then(|value| value.as_i64())
            .map(|value| value != 0)
            .ok_or_else(|| Error("captcha row is missing used".to_string()))?;
        if used {
            return Err(Error("captcha challenge has already been used".to_string()));
        }
        let expires = row
            .get("expires")
            .and_then(|value| value.as_str())
            .ok_or_else(|| Error("captcha row is missing expires".to_string()))?;
        let expires = chrono::DateTime::parse_from_rfc3339(expires)
            .map_err(|error| Error(format!("invalid captcha expiry {}: {}", expires, error)))?
            .with_timezone(&chrono::Utc);
        self.sqlite.execute(
            "UPDATE captchas SET used = 1 WHERE id = ?1",
            &[SQLiteValue::Text(id.to_string())],
        )?;
        if chrono::Utc::now() >= expires {
            return Err(Error("captcha challenge has expired".to_string()));
        }
        let rows = self.sqlite.query(
            "SELECT id FROM captchas WHERE id = ?1 AND answer_hash = ?2 LIMIT 1",
            &[
                SQLiteValue::Text(id.to_string()),
                SQLiteValue::Text(hash_secret(&answer)),
            ],
        )?;
        if rows.is_empty() {
            return Err(Error("captcha answer is invalid".to_string()));
        }
        Ok(())
    }

    pub fn captcha_clear_expired(&self) -> Result<usize, Error> {
        let now = chrono::Utc::now().to_rfc3339();
        let before = self.sqlite.query(
            "SELECT id FROM captchas WHERE expires <= ?1 OR used = 1",
            &[SQLiteValue::Text(now.clone())],
        )?;
        self.sqlite.execute(
            "DELETE FROM captchas WHERE expires <= ?1 OR used = 1",
            &[SQLiteValue::Text(now)],
        )?;
        Ok(before.len())
    }

    pub fn token_create(&self, ttl_seconds: u64) -> Result<(TokenRecord, String), Error> {
        let plaintext = generate_secret();
        let now = chrono::Utc::now();
        let expires = now
            .checked_add_signed(chrono::TimeDelta::seconds(ttl_seconds as i64))
            .ok_or_else(|| Error("failed to compute token expiry".to_string()))?;
        let record = TokenRecord {
            id: generate_token_id(),
            token: hash_secret(&plaintext),
            enabled: true,
            timestamp: now.to_rfc3339(),
            expires: expires.to_rfc3339(),
        };
        self.sqlite.execute(
            "INSERT INTO tokens (id, token, enabled, timestamp, expires)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &[
                SQLiteValue::Text(record.id.clone()),
                SQLiteValue::Text(record.token.clone()),
                SQLiteValue::Integer(if record.enabled { 1 } else { 0 }),
                SQLiteValue::Text(record.timestamp.clone()),
                SQLiteValue::Text(record.expires.clone()),
            ],
        )?;
        Ok((record, plaintext))
    }

    pub fn token_check(&self, token: &str) -> Result<bool, Error> {
        let token = token.trim();
        if token.is_empty() {
            return Ok(false);
        }
        let rows = self.sqlite.query(
            "SELECT enabled, expires
             FROM tokens
             WHERE token = ?1
             LIMIT 1",
            &[SQLiteValue::Text(hash_secret(token))],
        )?;
        let Some(row) = rows.into_iter().next() else {
            return Ok(false);
        };
        let enabled = row
            .get("enabled")
            .and_then(|value| value.as_i64())
            .map(|value| value != 0)
            .ok_or_else(|| Error("token row is missing enabled".to_string()))?;
        if !enabled {
            return Ok(false);
        }
        let expires = row
            .get("expires")
            .and_then(|value| value.as_str())
            .ok_or_else(|| Error("token row is missing expires".to_string()))?;
        let expires = chrono::DateTime::parse_from_rfc3339(expires)
            .map_err(|error| Error(format!("invalid token expiry {}: {}", expires, error)))?
            .with_timezone(&chrono::Utc);
        Ok(chrono::Utc::now() < expires)
    }

    pub fn token_disable(&self, id: &str) -> Result<bool, Error> {
        let id = id.trim();
        if id.is_empty() {
            return Err(Error("id must not be empty".to_string()));
        }
        self.sqlite.execute(
            "UPDATE tokens SET enabled = 0 WHERE id = ?1",
            &[SQLiteValue::Text(id.to_string())],
        )?;
        let rows = self.sqlite.query(
            "SELECT enabled FROM tokens WHERE id = ?1",
            &[SQLiteValue::Text(id.to_string())],
        )?;
        Ok(!rows.is_empty())
    }

    pub fn token_disable_value(&self, token: &str) -> Result<bool, Error> {
        let token = token.trim();
        if token.is_empty() {
            return Err(Error("token must not be empty".to_string()));
        }
        self.sqlite.execute(
            "UPDATE tokens SET enabled = 0 WHERE token = ?1",
            &[SQLiteValue::Text(hash_secret(token))],
        )?;
        let rows = self.sqlite.query(
            "SELECT enabled FROM tokens WHERE token = ?1",
            &[SQLiteValue::Text(hash_secret(token))],
        )?;
        Ok(!rows.is_empty())
    }

    pub fn token_clear(&self) -> Result<usize, Error> {
        let now = chrono::Utc::now().to_rfc3339();
        let before = self.sqlite.query(
            "SELECT id FROM tokens WHERE expires <= ?1",
            &[SQLiteValue::Text(now.clone())],
        )?;
        self.sqlite.execute(
            "DELETE FROM tokens WHERE expires <= ?1",
            &[SQLiteValue::Text(now)],
        )?;
        Ok(before.len())
    }

    pub fn user_create_with_key(
        &self,
        username: &str,
        role: &str,
        api_key: &str,
        reserved: bool,
        timestamp: Option<&str>,
    ) -> Result<UserRecord, Error> {
        let username = normalize_username(username)?;
        let role = normalize_role_name(role)?;
        let api_key = api_key.trim();
        if api_key.is_empty() {
            return Err(Error("api_key must not be empty".to_string()));
        }
        if self.role_get(role)?.is_none() {
            return Err(Error(format!("role {} does not exist", role)));
        }
        if self.user_get(&username)?.is_some() {
            return Err(Error(format!("user {} already exists", username)));
        }
        let record = UserRecord {
            username: username.to_string(),
            api_key: api_key.to_string(),
            role: role.to_string(),
            enabled: true,
            reserved,
            profile_picture: None,
            two_factor_enabled: false,
            two_factor_required: false,
            timestamp: timestamp
                .map(ToString::to_string)
                .unwrap_or_else(|| chrono::Utc::now().to_rfc3339()),
        };
        self.sqlite.execute(
            "INSERT INTO users (username, email, password_hash, role, api_key, enabled, reserved, profile_picture, two_factor_enabled, two_factor_required, two_factor_secret, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            &[
                SQLiteValue::Text(record.username.clone()),
                SQLiteValue::Text(String::new()),
                SQLiteValue::Text(String::new()),
                SQLiteValue::Text(record.role.clone()),
                SQLiteValue::Text(record.api_key.clone()),
                SQLiteValue::Integer(if record.enabled { 1 } else { 0 }),
                SQLiteValue::Integer(if record.reserved { 1 } else { 0 }),
                SQLiteValue::Null,
                SQLiteValue::Integer(if record.two_factor_enabled { 1 } else { 0 }),
                SQLiteValue::Integer(if record.two_factor_required { 1 } else { 0 }),
                SQLiteValue::Null,
                SQLiteValue::Text(record.timestamp.clone()),
            ],
        )?;
        Ok(record)
    }
}
