async fn run_server(
    state: Arc<AppState>,
    bind: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let upload_limit = state.ui.upload.sample.max_bytes;
    let router = Router::new()
        .route("/", get(index_page))
        .route("/api/v1/version", get(version_api))
        .route("/api/v1/token", post(create_token_api))
        .route("/api/v1/token/clear", post(clear_token_api))
        .route("/api/v1/auth/role/create", post(auth_role_create_api))
        .route("/api/v1/auth/role", get(auth_role_get_api))
        .route("/api/v1/auth/roles/search", get(auth_roles_search_api))
        .route("/api/v1/auth/role/delete", post(auth_role_delete_api))
        .route("/api/v1/auth/user/create", post(auth_user_create_api))
        .route("/api/v1/auth/user", get(auth_user_get_api))
        .route("/api/v1/auth/users/search", get(auth_users_search_api))
        .route("/api/v1/auth/user/disable", post(auth_user_disable_api))
        .route("/api/v1/auth/user/enable", post(auth_user_enable_api))
        .route("/api/v1/auth/user/reset", post(auth_user_reset_api))
        .route("/api/v1/index/graph", post(stage_index_graph))
        .route("/api/v1/index/function", post(stage_index_function))
        .route("/api/v1/index/block", post(stage_index_block))
        .route("/api/v1/index/instruction", post(stage_index_instruction))
        .route("/api/v1/index/commit", post(commit_index))
        .route("/api/v1/index/clear", post(clear_index))
        .route(
            "/api/v1/corpora/collection",
            get(get_collection_corpora_api),
        )
        .route(
            "/api/v1/corpora/collection/add",
            post(add_collection_corpus_api),
        )
        .route(
            "/api/v1/corpora/collection/remove",
            post(remove_collection_corpus_api),
        )
        .route("/api/v1/tags/sample", get(get_sample_tags))
        .route("/api/v1/tags/sample/add", post(add_sample_tag))
        .route("/api/v1/tags/sample/remove", post(remove_sample_tag))
        .route("/api/v1/tags/sample/replace", post(replace_sample_tags))
        .route("/api/v1/tags/search", get(search_tags_api))
        .route("/api/v1/tags/add", post(add_tag_api))
        .route("/api/v1/tags/collection", get(get_collection_tags))
        .route("/api/v1/tags/collection/add", post(add_collection_tag_api))
        .route(
            "/api/v1/tags/collection/remove",
            post(remove_collection_tag_api),
        )
        .route(
            "/api/v1/tags/collection/replace",
            post(replace_collection_tags_api),
        )
        .route("/api/v1/tags/search/sample", get(search_sample_tags_api))
        .route(
            "/api/v1/tags/search/collection",
            get(search_collection_tags_api),
        )
        .route("/api/v1/symbols/collection", get(get_collection_symbols))
        .route("/api/v1/symbols/search", get(search_symbols_api))
        .route("/api/v1/symbols/add", post(add_symbol_api))
        .route(
            "/api/v1/symbols/collection/add",
            post(add_collection_symbol_api),
        )
        .route(
            "/api/v1/symbols/collection/remove",
            post(remove_collection_symbol_api),
        )
        .route(
            "/api/v1/symbols/collection/replace",
            post(replace_collection_symbols_api),
        )
        .route("/api/v1/search", post(search_api))
        .route("/api/v1/search/detail", get(search_detail_api))
        .route("/api/v1/action/yara", post(action_yara_api))
        .route("/api/v1/corpora/add", post(add_corpus_api))
        .route("/api/v1/corpora", get(search_corpora_api))
        .route(
            "/api/v1/upload/sample",
            post(upload).layer(DefaultBodyLimit::max(upload_limit)),
        )
        .route("/api/v1/upload/status", get(upload_status))
        .route("/api/v1/download/sample", get(download_sample))
        .route("/api/v1/download/samples", get(download_samples))
        .route("/api/v1/download/json", get(download_json))
        .merge(SwaggerUi::new("/api/v1/docs").url("/api/v1/openapi.json", ApiDoc::openapi()))
        .layer(middleware::from_fn(binlex::server::request_id::middleware))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, router).await?;
    Ok(())
}
