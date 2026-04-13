async fn run_server(
    state: Arc<AppState>,
    bind: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let upload_limit = state.ui.upload.sample.max_bytes;
    let router = Router::new()
        .route("/", get(index_page))
        .route("/api/v1/version", get(version_api))
        .route("/api/v1/auth/bootstrap", post(auth_bootstrap_api))
        .route("/api/v1/auth/login", post(auth_login_api))
        .route("/api/v1/auth/login/2fa", post(auth_login_two_factor_api))
        .route(
            "/api/v1/auth/login/2fa/setup",
            post(auth_login_two_factor_setup_api),
        )
        .route(
            "/api/v1/auth/login/2fa/enable",
            post(auth_login_two_factor_enable_api),
        )
        .route("/api/v1/auth/logout", post(auth_logout_api))
        .route("/api/v1/auth/captcha", get(auth_captcha_api))
        .route("/api/v1/auth/register", post(auth_register_api))
        .route("/api/v1/auth/password/reset", post(auth_password_reset_api))
        .route("/api/v1/auth/username/check", get(auth_username_check_api))
        .route("/api/v1/auth/me", get(auth_me_api))
        .route("/api/v1/profile", get(profile_get_api).delete(profile_delete_api))
        .route("/api/v1/profile/password", post(profile_password_api))
        .route(
            "/api/v1/profile/2fa/setup",
            post(profile_two_factor_setup_api),
        )
        .route(
            "/api/v1/profile/2fa/enable",
            post(profile_two_factor_enable_api),
        )
        .route(
            "/api/v1/profile/2fa/disable",
            post(profile_two_factor_disable_api),
        )
        .route(
            "/api/v1/profile/picture",
            post(profile_picture_api).delete(profile_picture_delete_api),
        )
        .route(
            "/api/v1/profile/picture/{username}",
            get(profile_picture_get_api),
        )
        .route(
            "/api/v1/profile/key/regenerate",
            post(profile_key_regenerate_api),
        )
        .route(
            "/api/v1/profile/recovery/regenerate",
            post(profile_recovery_regenerate_api),
        )
        .route("/api/v1/admin/users", get(admin_users_api))
        .route("/api/v1/admin/users/create", post(admin_user_create_api))
        .route("/api/v1/admin/users/role", post(admin_user_role_api))
        .route("/api/v1/admin/users/enabled", post(admin_user_enabled_api))
        .route(
            "/api/v1/admin/corpora/{corpus}",
            axum::routing::delete(admin_delete_corpus_api),
        )
        .route(
            "/api/v1/admin/tags/{tag}",
            axum::routing::delete(admin_delete_tag_api),
        )
        .route(
            "/api/v1/admin/symbols/{symbol}",
            axum::routing::delete(admin_delete_symbol_api),
        )
        .route(
            "/api/v1/admin/users/password/reset",
            post(admin_user_password_reset_api),
        )
        .route(
            "/api/v1/admin/users/key/regenerate",
            post(admin_user_key_regenerate_api),
        )
        .route(
            "/api/v1/admin/users/{username}/picture",
            axum::routing::delete(admin_user_picture_delete_api),
        )
        .route(
            "/api/v1/admin/users/2fa/require",
            post(admin_user_two_factor_require_api),
        )
        .route(
            "/api/v1/admin/users/2fa/disable",
            post(admin_user_two_factor_disable_api),
        )
        .route(
            "/api/v1/admin/users/2fa/reset",
            post(admin_user_two_factor_reset_api),
        )
        .route(
            "/api/v1/admin/users/{username}",
            axum::routing::delete(admin_user_delete_api),
        )
        .route("/api/v1/index/graph", post(stage_index_graph))
        .route("/api/v1/index/function", post(stage_index_function))
        .route("/api/v1/index/block", post(stage_index_block))
        .route("/api/v1/index/instruction", post(stage_index_instruction))
        .route("/api/v1/index/commit", post(commit_index))
        .route("/api/v1/index/clear", post(clear_index))
        .route(
            "/api/v1/index/sample",
            post(upload).layer(DefaultBodyLimit::max(upload_limit)),
        )
        .route("/api/v1/index/status", get(upload_status))
        .route(
            "/api/v1/corpora/collection",
            get(get_collection_corpora_api)
                .post(add_collection_corpus_api)
                .delete(remove_collection_corpus_api),
        )
        .route("/api/v1/tags/search", get(search_tags_api))
        .route("/api/v1/tags", post(add_tag_api))
        .route(
            "/api/v1/tags/collection",
            get(get_collection_tags)
                .post(add_collection_tag_api)
                .delete(remove_collection_tag_api)
                .put(replace_collection_tags_api),
        )
        .route(
            "/api/v1/tags/search/collection",
            get(search_collection_tags_api),
        )
        .route(
            "/api/v1/symbols/collection",
            get(get_collection_symbols)
                .post(add_collection_symbol_api)
                .delete(remove_collection_symbol_api)
                .put(replace_collection_symbols_api),
        )
        .route("/api/v1/symbols/search", get(search_symbols_api))
        .route("/api/v1/symbols", post(add_symbol_api))
        .route("/api/v1/comments", get(get_entity_comments_api))
        .route("/api/v1/comments/add", post(add_entity_comment_api))
        .route(
            "/api/v1/comments/{id}",
            axum::routing::delete(delete_entity_comment_api),
        )
        .route("/api/v1/admin/comments", get(admin_comments_api))
        .route("/api/v1/search", post(search_api))
        .route("/api/v1/search/detail", get(search_detail_api))
        .route("/api/v1/graph", get(graph_api))
        .route("/api/v1/yara/render", post(action_yara_api))
        .route("/api/v1/corpora", get(search_corpora_api).post(add_corpus_api))
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
