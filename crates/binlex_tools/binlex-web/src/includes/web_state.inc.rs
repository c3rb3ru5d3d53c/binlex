struct AppState {
    ui: BinlexWebConfig,
    client: Server,
    index: LocalIndex,
    database: Arc<LocalDB>,
    analysis_config: Config,
    index_root: PathBuf,
    staged_indexes: Arc<Mutex<BTreeMap<String, LocalIndex>>>,
}

impl AppState {
    fn two_factor_required(&self) -> bool {
        self.ui.auth.two_factor.enabled && self.ui.auth.two_factor.required
    }

    fn staged_index(&self, token: &str) -> Result<LocalIndex, AppError> {
        if let Some(staged) = self.staged_indexes.lock().unwrap().get(token).cloned() {
            return Ok(staged);
        }
        let staged = LocalIndex::with_options(
            self.analysis_config.clone(),
            Some(self.index_root.clone()),
            self.index.config().index.local.dimensions,
        )
        .map_err(|error| AppError::new(error.to_string()))?;
        self.staged_indexes
            .lock()
            .unwrap()
            .insert(token.to_string(), staged.clone());
        Ok(staged)
    }

    fn remove_staged_index(&self, token: &str) -> Result<LocalIndex, AppError> {
        self.staged_indexes
            .lock()
            .unwrap()
            .remove(token)
            .ok_or_else(|| AppError::new("no staged indexing work for token"))
    }

    fn route_auth_rule(&self, path: &str) -> Option<&WebAuthRuleConfig> {
        self.ui.auth.rules.iter().find(|rule| {
            rule.path == path || (rule.path.ends_with('/') && path.starts_with(&rule.path))
        })
    }

    fn route_auth_enabled(&self, path: &str) -> bool {
        if !self.ui.auth.enabled {
            return false;
        }
        self.route_auth_rule(path)
            .map(|rule| rule.enabled)
            .unwrap_or(false)
    }

    fn route_auth_roles(&self, path: &str) -> Vec<String> {
        self.route_auth_rule(path)
            .map(|rule| rule.roles.clone())
            .unwrap_or_default()
    }

    fn route_token_enabled(&self, path: &str) -> bool {
        if !self.ui.token.enabled {
            return false;
        }
        self.ui
            .token
            .rules
            .iter()
            .find(|rule| {
                rule.path == path || (rule.path.ends_with('/') && path.starts_with(&rule.path))
            })
            .map(|rule| rule.enabled)
            .unwrap_or(false)
    }
}
