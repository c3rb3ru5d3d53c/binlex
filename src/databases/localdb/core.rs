use super::*;

impl LocalDB {
    pub fn new(config: &Config) -> Result<Self, Error> {
        Self::with_path(config, None::<&Path>)
    }

    pub fn with_path(config: &Config, path: Option<impl AsRef<Path>>) -> Result<Self, Error> {
        let path = path
            .as_ref()
            .map(|value| value.as_ref())
            .unwrap_or_else(|| Path::new(&config.databases.local.path));
        let db = Self {
            sqlite: SQLite::new(path)?,
        };
        db.initialize()?;
        Ok(db)
    }

    fn initialize(&self) -> Result<(), Error> {
        self.sqlite.execute_batch(
            "CREATE TABLE IF NOT EXISTS sample_status (
                sha256 TEXT PRIMARY KEY NOT NULL,
                status TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                error_message TEXT NULL,
                id TEXT NULL
            );
            DROP TABLE IF EXISTS sample_tags;
            CREATE TABLE IF NOT EXISTS tags (
                tag TEXT NOT NULL,
                username TEXT NOT NULL DEFAULT '',
                timestamp TEXT NOT NULL,
                PRIMARY KEY (tag)
            );
            CREATE TABLE IF NOT EXISTS collection_tags (
                sha256 TEXT NOT NULL,
                collection TEXT NOT NULL,
                address INTEGER NOT NULL,
                tag TEXT NOT NULL,
                username TEXT NOT NULL DEFAULT '',
                timestamp TEXT NOT NULL,
                PRIMARY KEY (sha256, collection, address, tag)
            );
            CREATE TABLE IF NOT EXISTS entity_corpora (
                sha256 TEXT NOT NULL,
                collection TEXT NOT NULL,
                architecture TEXT NOT NULL,
                address INTEGER NOT NULL,
                corpus TEXT NOT NULL,
                username TEXT NOT NULL DEFAULT '',
                timestamp TEXT NOT NULL,
                PRIMARY KEY (sha256, collection, architecture, address, corpus)
            );
            CREATE TABLE IF NOT EXISTS corpora_catalog (
                corpus TEXT NOT NULL,
                username TEXT NOT NULL DEFAULT '',
                timestamp TEXT NOT NULL,
                PRIMARY KEY (corpus)
            );
            CREATE TABLE IF NOT EXISTS entity_children (
                sha256 TEXT NOT NULL,
                architecture TEXT NOT NULL,
                parent_collection TEXT NOT NULL,
                parent_address INTEGER NOT NULL,
                child_collection TEXT NOT NULL,
                child_address INTEGER NOT NULL,
                PRIMARY KEY (
                    sha256,
                    architecture,
                    parent_collection,
                    parent_address,
                    child_collection,
                    child_address
                )
            );
            CREATE TABLE IF NOT EXISTS embedding_counts (
                collection TEXT NOT NULL,
                architecture TEXT NOT NULL,
                embedding TEXT NOT NULL,
                count INTEGER NOT NULL,
                PRIMARY KEY (collection, architecture, embedding)
            );
            CREATE TABLE IF NOT EXISTS entity_metadata (
                object_id TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                collection TEXT NOT NULL,
                architecture TEXT NOT NULL,
                username TEXT NOT NULL,
                address INTEGER NOT NULL,
                size INTEGER NOT NULL,
                cyclomatic_complexity INTEGER NULL,
                average_instructions_per_block REAL NULL,
                number_of_instructions INTEGER NULL,
                number_of_blocks INTEGER NULL,
                markov REAL NULL,
                entropy REAL NULL,
                contiguous INTEGER NULL,
                chromosome_entropy REAL NULL,
                collection_tag_count INTEGER NOT NULL DEFAULT 0,
                collection_tags_json TEXT NOT NULL DEFAULT '[]',
                collection_comment_count INTEGER NOT NULL DEFAULT 0,
                timestamp TEXT NOT NULL,
                vector_json TEXT NOT NULL,
                attributes_json TEXT NOT NULL,
                PRIMARY KEY (collection, architecture, object_id)
            );
            CREATE TABLE IF NOT EXISTS sample_comments (
                sha256 TEXT NOT NULL,
                comment TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                PRIMARY KEY (sha256, comment)
            );
            CREATE TABLE IF NOT EXISTS collection_comments (
                sha256 TEXT NOT NULL,
                collection TEXT NOT NULL,
                address INTEGER NOT NULL,
                comment TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                PRIMARY KEY (sha256, collection, address, comment)
            );
            CREATE TABLE IF NOT EXISTS entity_comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sha256 TEXT NOT NULL,
                collection TEXT NOT NULL,
                address INTEGER NOT NULL,
                username TEXT NOT NULL DEFAULT '',
                comment TEXT NOT NULL,
                timestamp TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_entity_comments_lookup
                ON entity_comments (sha256, collection, address, timestamp DESC, id DESC);
            CREATE INDEX IF NOT EXISTS idx_entity_comments_timestamp
                ON entity_comments (timestamp DESC, id DESC);
            CREATE TABLE IF NOT EXISTS symbols (
                symbol TEXT NOT NULL,
                username TEXT NOT NULL DEFAULT '',
                timestamp TEXT NOT NULL,
                PRIMARY KEY (symbol)
            );
            CREATE TABLE IF NOT EXISTS roles (
                name TEXT PRIMARY KEY NOT NULL,
                timestamp TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY NOT NULL,
                email TEXT NOT NULL DEFAULT '',
                password_hash TEXT NOT NULL DEFAULT '',
                role TEXT NOT NULL,
                api_key TEXT NOT NULL,
                enabled INTEGER NOT NULL,
                reserved INTEGER NOT NULL,
                profile_picture TEXT NULL,
                two_factor_enabled INTEGER NOT NULL DEFAULT 0,
                two_factor_required INTEGER NOT NULL DEFAULT 0,
                two_factor_secret TEXT NULL,
                timestamp TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY NOT NULL,
                session TEXT NOT NULL,
                username TEXT NOT NULL,
                enabled INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                expires TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS login_challenges (
                id TEXT PRIMARY KEY NOT NULL,
                challenge TEXT NOT NULL,
                username TEXT NOT NULL,
                setup_required INTEGER NOT NULL,
                enabled INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                expires TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS recovery_codes (
                username TEXT NOT NULL,
                code_hash TEXT NOT NULL,
                enabled INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                PRIMARY KEY (username, code_hash)
            );
            CREATE TABLE IF NOT EXISTS tokens (
                id TEXT PRIMARY KEY NOT NULL,
                token TEXT NOT NULL,
                enabled INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                expires TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS captchas (
                id TEXT PRIMARY KEY NOT NULL,
                answer_hash TEXT NOT NULL,
                used INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                expires TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_corpora_catalog_corpus ON corpora_catalog (corpus);
            CREATE INDEX IF NOT EXISTS idx_tags_tag ON tags (tag);
            CREATE INDEX IF NOT EXISTS idx_entity_corpora_lookup ON entity_corpora (sha256, collection, architecture, address);
            CREATE INDEX IF NOT EXISTS idx_entity_corpora_corpus ON entity_corpora (corpus);
            CREATE INDEX IF NOT EXISTS idx_entity_children_lookup ON entity_children (sha256, architecture, parent_collection, parent_address, child_collection);
            CREATE INDEX IF NOT EXISTS idx_embedding_counts_lookup ON embedding_counts (collection, architecture, embedding);
            CREATE INDEX IF NOT EXISTS idx_entity_metadata_sha256 ON entity_metadata (sha256);
            CREATE INDEX IF NOT EXISTS idx_entity_metadata_lookup ON entity_metadata (collection, architecture, object_id);
            CREATE INDEX IF NOT EXISTS idx_symbols_symbol ON symbols (symbol);
            CREATE INDEX IF NOT EXISTS idx_recovery_codes_username ON recovery_codes (username);
            CREATE INDEX IF NOT EXISTS idx_captchas_expires ON captchas (expires);",
        )?;
        for statement in [
            "ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE users ADD COLUMN password_hash TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE users ADD COLUMN profile_picture TEXT NULL",
            "ALTER TABLE users ADD COLUMN two_factor_enabled INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE users ADD COLUMN two_factor_required INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE users ADD COLUMN two_factor_secret TEXT NULL",
            "ALTER TABLE tags ADD COLUMN username TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE collection_tags ADD COLUMN username TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE entity_corpora ADD COLUMN username TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE corpora_catalog ADD COLUMN username TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE symbols ADD COLUMN username TEXT NOT NULL DEFAULT ''",
        ] {
            match self.sqlite.execute(statement, &[]) {
                Ok(_) => {}
                Err(error) if error.to_string().contains("duplicate column name") => {}
                Err(error) => return Err(error.into()),
            }
        }
        match self.sqlite.execute(
            "ALTER TABLE entity_metadata ADD COLUMN markov REAL NULL",
            &[],
        ) {
            Ok(_) => {}
            Err(error) if error.to_string().contains("duplicate column name") => {}
            Err(error) => return Err(error.into()),
        }
        match self.sqlite.execute(
            "ALTER TABLE entity_metadata ADD COLUMN collection_comment_count INTEGER NOT NULL DEFAULT 0",
            &[],
        ) {
            Ok(_) => {}
            Err(error) if error.to_string().contains("duplicate column name") => {}
            Err(error) => return Err(error.into()),
        }
        match self.sqlite.execute(
            "ALTER TABLE entity_metadata ADD COLUMN collection_tag_count INTEGER NOT NULL DEFAULT 0",
            &[],
        ) {
            Ok(_) => {}
            Err(error) if error.to_string().contains("duplicate column name") => {}
            Err(error) => return Err(error.into()),
        }
        match self.sqlite.execute(
            "ALTER TABLE entity_metadata ADD COLUMN collection_tags_json TEXT NOT NULL DEFAULT '[]'",
            &[],
        ) {
            Ok(_) => {}
            Err(error) if error.to_string().contains("duplicate column name") => {}
            Err(error) => return Err(error.into()),
        }
        self.cleanup_legacy_auth_state()?;
        self.ensure_reserved_auth_objects()?;
        self.ensure_default_corpora()?;
        Ok(())
    }

    fn ensure_default_corpora(&self) -> Result<(), Error> {
        for corpus in ["goodware", "malware"] {
            self.corpus_add(corpus, None, None)?;
        }
        Ok(())
    }

    fn cleanup_legacy_auth_state(&self) -> Result<(), Error> {
        self.sqlite.execute(
            "DELETE FROM sessions WHERE username IN (
                SELECT username FROM users WHERE coalesce(password_hash, '') = ''
            )",
            &[],
        )?;
        self.sqlite.execute(
            "DELETE FROM users WHERE coalesce(password_hash, '') = ''",
            &[],
        )?;
        Ok(())
    }

    pub(super) fn replace_recovery_codes(
        &self,
        username: &str,
        codes: &[String],
        timestamp: &str,
    ) -> Result<(), Error> {
        self.sqlite.execute(
            "DELETE FROM recovery_codes WHERE username = ?1",
            &[SQLiteValue::Text(username.to_string())],
        )?;
        for code in codes
            .iter()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        {
            self.sqlite.execute(
                "INSERT INTO recovery_codes (username, code_hash, enabled, timestamp)
                 VALUES (?1, ?2, ?3, ?4)",
                &[
                    SQLiteValue::Text(username.to_string()),
                    SQLiteValue::Text(hash_secret(code)),
                    SQLiteValue::Integer(1),
                    SQLiteValue::Text(timestamp.to_string()),
                ],
            )?;
        }
        Ok(())
    }

    pub(super) fn consume_recovery_code(
        &self,
        username: &str,
        recovery_code: &str,
        timestamp: Option<&str>,
    ) -> Result<String, Error> {
        let recovery_code = recovery_code.trim();
        if recovery_code.is_empty() {
            return Err(Error("recovery code must not be empty".to_string()));
        }
        let code_hash = hash_secret(recovery_code);
        let rows = self.sqlite.query(
            "SELECT enabled FROM recovery_codes
             WHERE username = ?1 AND code_hash = ?2
             LIMIT 1",
            &[
                SQLiteValue::Text(username.to_string()),
                SQLiteValue::Text(code_hash.clone()),
            ],
        )?;
        let Some(row) = rows.into_iter().next() else {
            return Err(Error("invalid recovery code".to_string()));
        };
        let enabled = row
            .get("enabled")
            .and_then(|value| value.as_i64())
            .map(|value| value != 0)
            .ok_or_else(|| Error("recovery code row is missing enabled".to_string()))?;
        if !enabled {
            return Err(Error("recovery code has already been used".to_string()));
        }
        let when = timestamp
            .map(ToString::to_string)
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
        self.sqlite.execute(
            "UPDATE recovery_codes SET enabled = 0, timestamp = ?1 WHERE username = ?2 AND code_hash = ?3",
            &[
                SQLiteValue::Text(when.clone()),
                SQLiteValue::Text(username.to_string()),
                SQLiteValue::Text(code_hash),
            ],
        )?;
        Ok(when)
    }

    fn ensure_reserved_auth_objects(&self) -> Result<(), Error> {
        let now = chrono::Utc::now().to_rfc3339();
        for role in ["admin", "user"] {
            if self.role_get(role)?.is_none() {
                self.role_create(role, Some(&now))?;
            }
        }
        Ok(())
    }
}
