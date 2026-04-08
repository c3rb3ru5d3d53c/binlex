struct AppState {
    ui: BinlexWebConfig,
    client: Server,
    index: LocalIndex,
    database: Arc<LocalDB>,
    analysis_config: Config,
    index_root: PathBuf,
    staged_indexes: Arc<Mutex<BTreeMap<String, LocalIndex>>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RouteAccessPolicy {
    Public,
    Authenticated,
    Admin,
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

    fn route_access_policy(&self, method: &axum::http::Method, path: &str) -> RouteAccessPolicy {
        if !self.ui.auth.enabled {
            return RouteAccessPolicy::Public;
        }
        if path.starts_with("/api/v1/admin/")
            || (method == axum::http::Method::POST && path == "/api/v1/corpora")
            || (path.starts_with("/api/v1/comments/") && method == axum::http::Method::DELETE)
        {
            return RouteAccessPolicy::Admin;
        }
        if matches!(
            (method, path),
            (&axum::http::Method::POST, "/api/v1/index/graph")
                | (&axum::http::Method::POST, "/api/v1/index/function")
                | (&axum::http::Method::POST, "/api/v1/index/block")
                | (&axum::http::Method::POST, "/api/v1/index/instruction")
                | (&axum::http::Method::POST, "/api/v1/index/commit")
                | (&axum::http::Method::POST, "/api/v1/index/clear")
                | (&axum::http::Method::POST, "/api/v1/index/sample")
                | (&axum::http::Method::POST, "/api/v1/corpora/collection")
                | (&axum::http::Method::DELETE, "/api/v1/corpora/collection")
                | (&axum::http::Method::POST, "/api/v1/tags")
                | (&axum::http::Method::POST, "/api/v1/tags/collection")
                | (&axum::http::Method::DELETE, "/api/v1/tags/collection")
                | (&axum::http::Method::PUT, "/api/v1/tags/collection")
                | (&axum::http::Method::POST, "/api/v1/symbols")
                | (&axum::http::Method::POST, "/api/v1/symbols/collection")
                | (&axum::http::Method::DELETE, "/api/v1/symbols/collection")
                | (&axum::http::Method::PUT, "/api/v1/symbols/collection")
                | (&axum::http::Method::POST, "/api/v1/comments/add")
                | (&axum::http::Method::GET, "/api/v1/profile")
                | (&axum::http::Method::DELETE, "/api/v1/profile")
                | (&axum::http::Method::POST, "/api/v1/profile/password")
                | (&axum::http::Method::POST, "/api/v1/profile/2fa/setup")
                | (&axum::http::Method::POST, "/api/v1/profile/2fa/enable")
                | (&axum::http::Method::POST, "/api/v1/profile/2fa/disable")
                | (&axum::http::Method::POST, "/api/v1/profile/picture")
                | (&axum::http::Method::DELETE, "/api/v1/profile/picture")
                | (&axum::http::Method::POST, "/api/v1/profile/key/regenerate")
                | (&axum::http::Method::POST, "/api/v1/profile/recovery/regenerate")
        ) {
            return RouteAccessPolicy::Authenticated;
        }
        RouteAccessPolicy::Public
    }
}
