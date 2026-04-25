async fn index_page(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<RequestAuthContext>,
    Extension(request_id): Extension<RequestId>,
    Query(mut params): Query<PageParams>,
) -> Result<Html<String>, AppError> {
    clamp_top_k(&mut params);
    clamp_page(&mut params);
    let state_for_page = state.clone();
    let request_id_for_page = request_id.to_string();
    let auth_user = auth.user.clone();
    let data = task::spawn_blocking(move || {
        build_page_data(
            state_for_page.as_ref(),
            params,
            &request_id_for_page,
            auth_user,
        )
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))??;
    Ok(Html(render_page(&data)))
}

#[utoipa::path(
    post,
    path = "/api/v1/search",
    tag = "Search",
    request_body = SearchRequest,
    responses(
        (status = 200, description = "Search results data payload.", body = SearchResponse)
    )
)]
async fn search_api(
    State(state): State<Arc<AppState>>,
    Extension(request_id): Extension<RequestId>,
    Json(mut request): Json<SearchRequest>,
) -> Result<Json<SearchResponse>, AppError> {
    clamp_search_request_top_k(&mut request);
    clamp_search_request_page(&mut request);
    let state_for_page = state.clone();
    let request_id_for_page = request_id.to_string();
    let params = PageParams {
        search: Some("1".to_string()),
        query: request.query,
        top_k: request.top_k,
        page: request.page,
        ..PageParams::default()
    };
    let data = task::spawn_blocking(move || {
        build_page_data(state_for_page.as_ref(), params, &request_id_for_page, None)
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))??;
    Ok(Json(build_search_response(&data)))
}

#[utoipa::path(
    post,
    path = "/api/v1/yara/render",
    tag = "Action",
    request_body = ActionYaraRequest,
    responses(
        (status = 200, description = "Rendered YARA rule text.", content_type = "text/plain", body = String),
        (status = 400, description = "Invalid request.", body = ApiErrorResponse)
    )
)]
async fn action_yara_api(
    State(state): State<Arc<AppState>>,
    Extension(request_id): Extension<RequestId>,
    Json(request): Json<ActionYaraRequest>,
) -> Result<impl IntoResponse, AppError> {
    let state_for_action = state.clone();
    let request_id_for_action = request_id.to_string();
    let payload = task::spawn_blocking(move || {
        build_action_yara_rule(state_for_action.as_ref(), &request).map_err(|error| {
            AppError::with_request_id(error.to_string(), request_id_for_action.clone())
        })
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))??;
    Ok((
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        )],
        payload,
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/llvm/render",
    tag = "Action",
    params(SearchDetailParams),
    responses(
        (status = 200, description = "Rendered raw LLVM IR for a single indexed entity.", content_type = "text/plain", body = String),
        (status = 400, description = "Invalid request.", body = ApiErrorResponse)
    )
)]
async fn action_llvm_render_api(
    State(state): State<Arc<AppState>>,
    Extension(request_id): Extension<RequestId>,
    Query(params): Query<SearchDetailParams>,
) -> Result<impl IntoResponse, AppError> {
    let collection = parse_collection(&params.collection)
        .ok_or_else(|| AppError::with_request_id("invalid collection", request_id.to_string()))?;
    let state_for_action = state.clone();
    let request_id_for_action = request_id.to_string();
    let payload = task::spawn_blocking(move || {
        render_entity_llvm_ir(
            state_for_action.as_ref(),
            &params.sha256,
            collection,
            &params.architecture,
            params.address,
        )
        .map_err(|error| AppError::with_request_id(error.to_string(), request_id_for_action))
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))??;
    Ok((
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        )],
        payload,
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/search/detail",
    tag = "Search",
    params(SearchDetailParams),
    responses(
        (status = 200, description = "Detailed search row payload.", body = SearchRowDetailResponse),
        (status = 400, description = "Invalid request.", body = ApiErrorResponse)
    )
)]
async fn search_detail_api(
    State(state): State<Arc<AppState>>,
    Extension(request_id): Extension<RequestId>,
    Query(params): Query<SearchDetailParams>,
) -> Result<Json<SearchRowDetailResponse>, AppError> {
    let collection = parse_collection(&params.collection)
        .ok_or_else(|| AppError::with_request_id("invalid collection", request_id.to_string()))?;
    let state_for_detail = state.clone();
    let request_id_for_detail = request_id.to_string();
    let params_for_detail = params;
    let detail = task::spawn_blocking(move || {
        let result = state_for_detail
            .index
            .result_detail(
                &params_for_detail.sha256,
                collection,
                &params_for_detail.architecture,
                params_for_detail.address,
                params_for_detail.symbol.as_deref(),
            )
            .map_err(|error| {
                AppError::with_request_id(error.to_string(), request_id_for_detail.clone())
            })?;
        Ok::<SearchRowDetailResponse, AppError>(build_search_row_detail_response(&result))
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))??;
    Ok(Json(detail))
}

pub(crate) fn build_search_response(data: &PageData) -> SearchResponse {
    SearchResponse {
        message: data.message.clone(),
        warning: data.warning.clone(),
        error: data.error.clone(),
        query: data.query.clone(),
        uploaded_sha256: data.uploaded_sha256.clone(),
        page: data.page,
        top_k: data.top_k,
        total_results: data.total_results,
        has_previous_page: data.has_previous_page,
        has_next_page: data.has_next_page,
        sample_downloads_enabled: data.sample_downloads_enabled,
        results: data.rows.iter().map(build_search_row_response).collect(),
    }
}

fn display_result_username(value: &str) -> String {
    if value.eq_ignore_ascii_case("anonymous") {
        return String::new();
    }
    value.to_string()
}

pub(crate) fn build_search_row_response(row: &ResultRow) -> SearchRowResponse {
    let result = &row.result;
    SearchRowResponse {
        side: row.side.as_api_str().to_string(),
        grouped: row.grouped,
        group_end: row.group_end,
        detail_loaded: false,
        object_id: result.object_id().to_string(),
        timestamp: result.timestamp().to_rfc3339(),
        username: display_result_username(result.username()),
        profile_picture: row.profile_picture.clone(),
        size: result.size(),
        score: row.score,
        similarity_score: row.score,
        vector: result.vector().to_vec(),
        json: result.json().cloned(),
        symbol: result.symbol().map(ToString::to_string),
        architecture: result.architecture().to_string(),
        sha256: result.sha256().to_string(),
        collection: result.collection().as_str().to_string(),
        address: result.address(),
        cyclomatic_complexity: result.cyclomatic_complexity(),
        average_instructions_per_block: result.average_instructions_per_block(),
        number_of_instructions: result.number_of_instructions(),
        number_of_blocks: result.number_of_blocks(),
        markov: result.markov(),
        entropy: result.entropy(),
        contiguous: result.contiguous(),
        chromosome_entropy: result.chromosome_entropy(),
        embedding: result.embedding().to_string(),
        embeddings: result.embeddings(),
        corpora: result.corpora().to_vec(),
        corpora_count: result.corpora().len(),
        collection_tag_count: row.collection_tag_count,
        collection_comment_count: row.collection_comment_count,
        sample_project_count: row.sample_project_count,
    }
}

fn build_action_yara_rule(
    state: &AppState,
    request: &ActionYaraRequest,
) -> Result<String, AppError> {
    if request.items.is_empty() {
        return Err(AppError::new("no items were provided"));
    }
    let mut rule = Rule::new();
    if !request.query.trim().is_empty() {
        rule.set_comment(request.query.trim());
    }
    let mut grouped = BTreeMap::<(String, String), Vec<(Collection, u64)>>::new();
    for item in &request.items {
        let collection = parse_collection(&item.collection)
            .ok_or_else(|| AppError::new("invalid collection"))?;
        grouped
            .entry((item.corpus.clone(), item.sha256.clone()))
            .or_default()
            .push((collection, item.address));
    }
    let mut seen = BTreeSet::new();
    let mut included = 0usize;
    for ((corpus, sha256), items) in grouped {
        let graph = state
            .index
            .sample_load(&corpus, &sha256)
            .map_err(|error| AppError::new(error.to_string()))?;
        for (collection, address) in items {
            let Some(pattern) = yara_pattern_for_entity(&graph, collection, address) else {
                continue;
            };
            if !seen.insert(pattern.clone()) {
                continue;
            }
            let comment = format!(
                "sample:{} collection:{} address:0x{:x}",
                sha256,
                collection.as_str(),
                address
            );
            rule.add_pattern(&pattern, Some(&comment));
            included = included.saturating_add(1);
        }
    }
    if rule.get_patterns().is_empty() {
        return Err(AppError::new(
            "no chromosome patterns available for YARA generation",
        ));
    }
    rule.set_condition("1 of them");
    if included == 0 {
        return Err(AppError::new(
            "no chromosome patterns available for YARA generation",
        ));
    }
    Ok(rule.render())
}

fn yara_pattern_for_entity(
    graph: &binlex::controlflow::Graph,
    entity: Collection,
    address: u64,
) -> Option<String> {
    let pattern = match entity {
        Collection::Instruction => graph.get_instruction(address)?.chromosome_json().pattern,
        Collection::Block => {
            binlex::controlflow::Block::new(address, graph)
                .ok()?
                .chromosome_json()
                .pattern
        }
        Collection::Function => {
            binlex::controlflow::Function::new(address, graph)
                .ok()?
                .chromosome_json()?
                .pattern
        }
    };
    let pattern = pattern.trim();
    if pattern.is_empty() {
        None
    } else {
        Some(pattern.to_string())
    }
}

fn build_search_row_detail_response(result: &SearchResult) -> SearchRowDetailResponse {
    SearchRowDetailResponse {
        detail_loaded: true,
        object_id: result.object_id().to_string(),
        timestamp: result.timestamp().to_rfc3339(),
        username: display_result_username(result.username()),
        size: result.size(),
        score: None,
        similarity_score: None,
        vector: result.vector().to_vec(),
        json: result.json().cloned(),
        symbol: result.symbol().map(ToString::to_string),
        architecture: result.architecture().to_string(),
        sha256: result.sha256().to_string(),
        collection: result.collection().as_str().to_string(),
        address: result.address(),
        cyclomatic_complexity: result.cyclomatic_complexity(),
        average_instructions_per_block: result.average_instructions_per_block(),
        number_of_instructions: result.number_of_instructions(),
        number_of_blocks: result.number_of_blocks(),
        markov: result.markov(),
        entropy: result.entropy(),
        contiguous: result.contiguous(),
        chromosome_entropy: result.chromosome_entropy(),
        embedding: result.embedding().to_string(),
        embeddings: result.embeddings(),
        corpora: result.corpora().to_vec(),
        corpora_count: result.corpora().len(),
    }
}

fn render_entity_llvm_ir(
    state: &AppState,
    sha256: &str,
    collection: Collection,
    architecture: &str,
    address: u64,
) -> Result<String, AppError> {
    let sha256 = sha256.trim();
    let architecture = architecture.trim();
    if !is_sha256(sha256) {
        return Err(AppError::new("invalid sha256"));
    }
    if architecture.is_empty() {
        return Err(AppError::new("architecture is required"));
    }
    let graph = state
        .index
        .graph_by_sha256(sha256)
        .map_err(|error| AppError::new(error.to_string()))?;
    if !graph.architecture.to_string().eq_ignore_ascii_case(architecture) {
        return Err(AppError::new(
            "requested architecture does not match indexed graph",
        ));
    }

    let mut config = state.analysis_config.clone();
    match collection {
        Collection::Instruction => config.instructions.lifters.llvm.enabled = true,
        Collection::Block => config.blocks.lifters.llvm.enabled = true,
        Collection::Function => config.functions.lifters.llvm.enabled = true,
    }

    let mut lifter = binlex::lifters::llvm::Lifter::new(graph.architecture, config);
    match collection {
        Collection::Instruction => {
            let instruction = graph
                .get_instruction(address)
                .ok_or_else(|| AppError::new("instruction not found"))?;
            lifter
                .lift_instruction(&instruction)
                .map_err(|error| AppError::new(error.to_string()))?;
        }
        Collection::Block => {
            let block = binlex::controlflow::Block::new(address, &graph)
                .map_err(|error| AppError::new(error.to_string()))?;
            lifter
                .lift_block(&block)
                .map_err(|error| AppError::new(error.to_string()))?;
        }
        Collection::Function => {
            let function = binlex::controlflow::Function::new(address, &graph)
                .map_err(|error| AppError::new(error.to_string()))?;
            lifter
                .lift_function(&function)
                .map_err(|error| AppError::new(error.to_string()))?;
        }
    }
    Ok(lifter.text())
}
fn build_page_data(
    state: &AppState,
    mut params: PageParams,
    request_id: &str,
    auth_user: Option<binlex::databases::UserRecord>,
) -> Result<PageData, AppError> {
    let corpora_options = state
        .index
        .corpus_search("", state.ui.api.corpora.max_results)
        .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?;
    let architecture_options = query_architecture_values();
    let mut collection_options = query_collection_values();
    collection_options.sort();
    let query_completion_specs = query_completion_specs();
    let upload_corpora_locked = state.ui.index.local.lock_corpora;
    let upload_corpus_options = upload_corpus_options(state, &corpora_options);
    let upload_selected_corpora = upload_default_selected_corpora(state, &upload_corpus_options);
    let upload_tag_options = state
        .database
        .tag_search("", state.ui.api.tags.max_results)
        .map(|page| page.items.into_iter().map(|item| item.tag).collect())
        .unwrap_or_default();
    let upload_selected_tags = Vec::new();
    let auth_bootstrap_required = state.database.user_count().unwrap_or(0) == 0;
    let can_write = auth_user.is_some() && !auth_bootstrap_required;
    let auth_user_profile = auth_user.as_ref().map(|user| AuthUserProfile {
        username: user.username.clone(),
        key: user.api_key.clone(),
        role: user.role.clone(),
        profile_picture: avatar_url_for_user(
            &user.username,
            user.profile_picture.as_deref(),
            Some(&user.timestamp),
        ),
        two_factor_enabled: user.two_factor_enabled,
        two_factor_required: user.two_factor_required,
    });

    let status = UiStatus {
        server_ok: state
            .client
            .health_with_request_id(Some(request_id))
            .is_ok(),
        index_ok: state.ui.index.local.enabled,
        database_ok: state
            .database
            .sample_status_get("__binlex_health__")
            .is_ok(),
    };
    info!(
        "page request request_id={} search={} query_len={} top_k={} server_ok={} index_ok={} database_ok={}",
        request_id,
        params.search.is_some(),
        params.query.len(),
        params.top_k.unwrap_or(DEFAULT_TOP_K),
        status.server_ok,
        status.index_ok,
        status.database_ok
    );

    let current_page = params.page.unwrap_or(1);
    let mut rows = Vec::new();
    let mut total_results = 0usize;
    let mut has_next_page = false;
    let mut warning = params.warning.clone();
    if params.search.is_some() {
        match execute_search(state, &params) {
            Ok(search_page) => {
                info!(
                    "page search completed request_id={} results={} page={} has_next={}",
                    request_id,
                    search_page.rows.len(),
                    current_page,
                    search_page.has_next
                );
                total_results = search_page.total_results;
                has_next_page = search_page.has_next;
                rows = search_page.rows;
                let tag_count_keys = rows
                    .iter()
                    .map(|row| {
                        (
                            row.result.sha256().to_string(),
                            row.result.collection(),
                            row.result.address(),
                        )
                    })
                    .collect::<Vec<_>>();
                let comment_count_keys = tag_count_keys.clone();
                let tag_counts =
                    state
                        .index
                        .collection_tag_counts(&tag_count_keys)
                        .map_err(|error| {
                            AppError::with_request_id(error.to_string(), request_id.to_string())
                        })?;
                let comment_counts = state
                    .index
                    .entity_comment_counts(&comment_count_keys)
                    .map_err(|error| {
                        AppError::with_request_id(error.to_string(), request_id.to_string())
                    })?;
                let project_counts = state
                    .database
                    .sample_project_counts(
                        &rows.iter()
                            .map(|row| row.result.sha256().to_string())
                            .collect::<Vec<_>>(),
                    )
                    .map_err(|error| {
                        AppError::with_request_id(error.to_string(), request_id.to_string())
                    })?;
                for row in &mut rows {
                    row.collection_tag_count = *tag_counts
                        .get(&(
                            row.result.sha256().to_string(),
                            row.result.collection(),
                            row.result.address(),
                        ))
                        .unwrap_or(&0);
                    row.collection_comment_count = *comment_counts
                        .get(&(
                            row.result.sha256().to_string(),
                            row.result.collection(),
                            row.result.address(),
                        ))
                        .unwrap_or(&0);
                    row.sample_project_count =
                        *project_counts.get(row.result.sha256()).unwrap_or(&0);
                    let username = row.result.username();
                    if !username.is_empty()
                        && let Some(user) = state.database.user_get(username).ok().flatten()
                    {
                        row.profile_picture = avatar_url_for_user(
                            &user.username,
                            user.profile_picture.as_deref(),
                            Some(&user.timestamp),
                        );
                    }
                }
                if search_page.warning.is_some() {
                    warning = search_page.warning;
                }
            }
            Err(error) => {
                warn!(
                    "page search failed request_id={} error={}",
                    request_id, error
                );
                params.error = Some(format!("{} Request ID: {}", error, request_id));
            }
        }
    } else {
        info!("page render without search request_id={}", request_id);
    }
    if let Some(message) = &params.message {
        info!("page message={}", message);
    }
    if let Some(warning) = &warning {
        warn!("page warning request_id={} warning={}", request_id, warning);
    }
    if let Some(error) = &params.error {
        warn!("page error request_id={} error={}", request_id, error);
    }

    Ok(PageData {
        corpora_options,
        architecture_options,
        collection_options,
        query_completion_specs,
        status,
        uploaded_sha256: params.uploaded_sha256.clone(),
        message: params.message.clone(),
        warning,
        error: params.error.clone(),
        query: params.query.clone(),
        top_k: params.top_k.unwrap_or(DEFAULT_TOP_K),
        page: current_page,
        total_results,
        has_previous_page: current_page > 1,
        has_next_page,
        rows,
        upload_format_options: vec![
            "Auto".to_string(),
            "PE".to_string(),
            "ELF".to_string(),
            "Mach-O".to_string(),
            "Shellcode".to_string(),
        ],
        upload_architecture_options: vec![
            "Auto".to_string(),
            display_architecture("amd64"),
            display_architecture("i386"),
            display_architecture("cil"),
        ],
        upload_corpus_options,
        upload_default_corpus: state.ui.index.local.default_corpus.clone(),
        upload_corpora_locked,
        upload_selected_corpora,
        upload_tag_options,
        upload_selected_tags,
        uploads_enabled: state.ui.upload.sample.enabled || state.ui.upload.project_files.enabled,
        upload_button_enabled:
            (state.ui.upload.sample.enabled || state.ui.upload.project_files.enabled) && can_write,
        sample_downloads_enabled: state.ui.download.sample.enabled
            || state.ui.download.samples.enabled,
        auth_bootstrap_required,
        auth_registration_enabled: state.ui.auth.registration.enabled,
        auth_two_factor_required: state.two_factor_required(),
        auth_user: auth_user_profile,
    })
}

#[utoipa::path(
    post,
    path = "/api/v1/corpora",
    tag = "Search",
    request_body = CorpusActionRequest,
    responses(
        (status = 200, description = "Added a corpus name.", body = TagsActionResponse),
        (status = 400, description = "Invalid request.", body = ApiErrorResponse)
    )
)]
async fn add_corpus_api(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestAuthContext>,
    Extension(request_id): Extension<RequestId>,
    Json(request): Json<CorpusActionRequest>,
) -> Result<Json<TagsActionResponse>, AppError> {
    let corpus = request.corpus.trim().to_string();
    if corpus.is_empty() {
        return Err(AppError::with_request_id(
            "corpus must not be empty",
            request_id.to_string(),
        ));
    }
    let username = context
        .user
        .as_ref()
        .map(|user| user.username.clone())
        .ok_or_else(|| AppError::unauthorized("authentication is required"))?;
    let state_for_work = state.clone();
    task::spawn_blocking(move || {
        state_for_work
            .database
            .corpus_add(&corpus, None, Some(&username))
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?;
    Ok(Json(TagsActionResponse { ok: true }))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/corpora/{corpus}",
    tag = "Admin",
    security(("bearer_auth" = [])),
    params(
        ("corpus" = String, Path, description = "Corpus name")
    ),
    responses((status = 200, description = "Deleted a corpus globally.", body = TagsActionResponse))
)]
async fn admin_delete_corpus_api(
    State(state): State<Arc<AppState>>,
    Extension(request_id): Extension<RequestId>,
    Path(corpus): Path<String>,
) -> Result<Json<TagsActionResponse>, AppError> {
    let corpus = corpus.trim().to_string();
    if corpus.is_empty() {
        return Err(AppError::with_request_id(
            "corpus must not be empty",
            request_id.to_string(),
        ));
    }
    let state_for_work = state.clone();
    task::spawn_blocking(move || {
        state_for_work
            .database
            .corpus_delete_global(&corpus)
            .map_err(|error| AppError::new(error.to_string()))?;
        state_for_work
            .index
            .corpus_delete(&corpus)
            .map_err(|error| AppError::new(error.to_string()))?;
        state_for_work
            .index
            .commit()
            .map_err(|error| AppError::new(error.to_string()))
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))??;
    Ok(Json(TagsActionResponse { ok: true }))
}

#[utoipa::path(
    get,
    path = "/api/v1/corpora",
    tag = "Search",
    params(CorporaApiParams),
    responses(
        (status = 200, description = "Matching corpora names.", body = CorporaCatalogResponse),
        (status = 400, description = "Invalid request.", body = ApiErrorResponse)
    )
)]
async fn search_corpora_api(
    State(state): State<Arc<AppState>>,
    Extension(request_id): Extension<RequestId>,
    Query(params): Query<CorporaApiParams>,
) -> Result<Json<CorporaCatalogResponse>, AppError> {
    if params.q.len() > state.ui.api.corpora.max_query_length {
        return Err(AppError::with_request_id(
            format!(
                "corpora query exceeds max length of {} characters",
                state.ui.api.corpora.max_query_length
            ),
            request_id.to_string(),
        ));
    }
    info!("corpora api request_id={} query={}", request_id, params.q);
    let state = state.clone();
    let max_results = state.ui.api.corpora.max_results;
    let values = task::spawn_blocking(move || {
        let indexed = state
            .index
            .corpus_search(&params.q, max_results)
            .map_err(|error| error.to_string())?;
        let catalog = state
            .database
            .corpus_search_details(&params.q, max_results)
            .map_err(|error| error.to_string())?;
        let mut values = indexed
            .into_iter()
            .map(|name| MetadataItemResponse {
                name,
                created_by: MetadataUserResponse {
                    username: String::new(),
                    profile_picture: None,
                },
                created_timestamp: String::new(),
                assigned_by: None,
                assigned_timestamp: None,
            })
            .collect::<Vec<_>>();
        for item in catalog {
            if values
                .iter()
                .any(|existing| existing.name.eq_ignore_ascii_case(&item.corpus))
            {
                continue;
            }
            let (profile_picture, timestamp) = if item.username.is_empty() {
                (None, None)
            } else if let Some(user) = state.database.user_get(&item.username).ok().flatten() {
                (user.profile_picture, Some(user.timestamp))
            } else {
                (None, None)
            };
            values.push(MetadataItemResponse {
                name: item.corpus,
                created_by: MetadataUserResponse {
                    username: item.username.clone(),
                    profile_picture: avatar_url_for_user(
                        &item.username,
                        profile_picture.as_deref(),
                        timestamp.as_deref(),
                    ),
                },
                created_timestamp: item.timestamp,
                assigned_by: None,
                assigned_timestamp: None,
            });
        }
        values.sort_by(|lhs, rhs| {
            lhs.name
                .to_ascii_lowercase()
                .cmp(&rhs.name.to_ascii_lowercase())
        });
        if values.len() > max_results {
            values.truncate(max_results);
        }
        let total_results = values.len();
        Ok::<CorporaCatalogResponse, String>(CorporaCatalogResponse {
            corpora: values,
            total_results,
        })
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?;
    info!(
        "corpora api request_id={} results={}",
        request_id,
        values.corpora.len()
    );
    Ok(Json(values))
}
fn execute_search(state: &AppState, params: &PageParams) -> Result<SearchPage, String> {
    let limit = params.top_k.unwrap_or(DEFAULT_TOP_K);
    let page = params.page.unwrap_or(1);
    let offset = page.saturating_sub(1).saturating_mul(limit);
    let query = params.query.trim();
    if query.is_empty() {
        return Err("enter a search query".to_string());
    }
    let plan = build_query_plan(
        &state.index,
        &state.ui.index.local.default_corpus,
        &default_collections(&state.ui.index.local),
        query,
    )
    .map_err(|error| error.to_string())?;
    execute_stream_search(state, &plan, limit, page, offset)
}

fn execute_stream_search(
    state: &AppState,
    plan: &StreamPlan,
    limit: usize,
    page: usize,
    offset: usize,
) -> Result<SearchPage, String> {
    let candidate_limit = state.ui.compare.limit.clamp(64, 4096);
    let show_score = stream_score_visible(plan);
    let (stream, warning) = evaluate_stream(state, plan, candidate_limit, limit, page)?;
    match stream {
        ExecutedStream::Search { results, side } => {
            let total_results = results.len();
            let has_next = results.len() > offset.saturating_add(limit);
            let rows = results
                .iter()
                .skip(offset)
                .take(limit)
                .cloned()
                .map(|result| ResultRow {
                    side,
                    score: show_score.then_some(result.score()),
                    profile_picture: None,
                    collection_comment_count: result.collection_comment_count() as usize,
                    result,
                    grouped: false,
                    group_end: false,
                    collection_tag_count: 0,
                    sample_project_count: 0,
                })
                .collect::<Vec<_>>();
            Ok(SearchPage {
                rows,
                total_results,
                has_next,
                warning,
            })
        }
        ExecutedStream::Compare { pairs } => {
            let total_results = pairs.len();
            let has_next = pairs.len() > offset.saturating_add(limit);
            let pairs = pairs
                .into_iter()
                .skip(offset)
                .take(limit)
                .collect::<Vec<_>>();
            let mut rows = Vec::with_capacity(pairs.len().saturating_mul(2));
            for pair in pairs {
                rows.push(ResultRow {
                    side: RowSide::Lhs,
                    score: Some(pair.score),
                    profile_picture: None,
                    collection_comment_count: pair.lhs.collection_comment_count() as usize,
                    result: pair.lhs,
                    grouped: true,
                    group_end: false,
                    collection_tag_count: 0,
                    sample_project_count: 0,
                });
                rows.push(ResultRow {
                    side: RowSide::Rhs,
                    score: Some(pair.score),
                    profile_picture: None,
                    collection_comment_count: pair.rhs.collection_comment_count() as usize,
                    result: pair.rhs,
                    grouped: true,
                    group_end: true,
                    collection_tag_count: 0,
                    sample_project_count: 0,
                });
            }
            Ok(SearchPage {
                rows,
                total_results,
                has_next,
                warning,
            })
        }
    }
}

fn stream_score_visible(plan: &StreamPlan) -> bool {
    match plan {
        StreamPlan::Search(plan) => matches!(plan.root, Some(SearchRoot::Vector(_))),
        StreamPlan::Compare { .. } => true,
        StreamPlan::Pipe { input, .. } => stream_score_visible(input),
    }
}

fn collect_search_candidates(
    state: &AppState,
    plan: &crate::query::SearchPlan,
    broad_limit: usize,
    limit: usize,
    page: usize,
) -> Result<Vec<SearchResult>, String> {
    let mut candidates = match &plan.root {
        Some(SearchRoot::Sha256(sha256)) => {
            info!(
                "search root=sha256 sha256={} corpora={:?} collections={:?} architectures={:?} top_k={}",
                sha256, plan.corpora, plan.collections, plan.architectures, limit
            );
            if search_requires_full_exact_scan(plan.query.expr()) {
                collect_exact_search_candidates(state, plan, sha256, broad_limit)?
            } else {
                state
                    .index
                    .exact_search_page(
                        &plan.corpora,
                        sha256,
                        Some(&plan.collections),
                        &plan.architectures,
                        0,
                        broad_limit,
                    )
                    .map_err(|error| error.to_string())?
            }
        }
        Some(SearchRoot::Embedding(embedding)) => {
            info!(
                "search root=embedding embedding={} corpora={:?} collections={:?} architectures={:?} top_k={} page={}",
                embedding, plan.corpora, plan.collections, plan.architectures, limit, page
            );
            state
                .index
                .embedding_search_page(
                    &plan.corpora,
                    embedding,
                    Some(&plan.collections),
                    &plan.architectures,
                    0,
                    broad_limit,
                )
                .map_err(|error| error.to_string())?
        }
        Some(SearchRoot::Vector(vector)) => {
            info!(
                "search root=vector dims={} corpora={:?} collections={:?} architectures={:?} top_k={} page={}",
                vector.len(),
                plan.corpora,
                plan.collections,
                plan.architectures,
                limit,
                page
            );
            state
                .index
                .nearest_page(
                    &plan.corpora,
                    vector,
                    Some(&plan.collections),
                    &plan.architectures,
                    0,
                    broad_limit,
                )
                .map_err(|error| error.to_string())?
        }
        None => {
            info!(
                "search root=scan corpora={:?} collections={:?} architectures={:?} top_k={} page={}",
                plan.corpora, plan.collections, plan.architectures, limit, page
            );
            if search_requires_full_scan(plan.query.expr()) {
                collect_scan_search_candidates(state, plan, broad_limit)?
            } else {
                state
                    .index
                    .scan_search_page(
                        &plan.corpora,
                        Some(&plan.collections),
                        &plan.architectures,
                        0,
                        broad_limit,
                    )
                    .map_err(|error| error.to_string())?
            }
        }
    };
    candidates.retain(|result| search_expr_matches(result, plan.query.expr(), &plan.root));
    Ok(candidates)
}

fn search_requires_full_scan(expr: &binlex::query::QueryExpr) -> bool {
    match expr {
        binlex::query::QueryExpr::Term(term) => !matches!(
            term.field,
            binlex::query::QueryField::Corpus
                | binlex::query::QueryField::Collection
                | binlex::query::QueryField::Architecture
        ),
        binlex::query::QueryExpr::Not(inner) => search_requires_full_scan(inner),
        binlex::query::QueryExpr::And(lhs, rhs) | binlex::query::QueryExpr::Or(lhs, rhs) => {
            search_requires_full_scan(lhs) || search_requires_full_scan(rhs)
        }
    }
}

fn search_requires_full_exact_scan(expr: &binlex::query::QueryExpr) -> bool {
    match expr {
        binlex::query::QueryExpr::Term(term) => !matches!(
            term.field,
            binlex::query::QueryField::Sha256
                | binlex::query::QueryField::Corpus
                | binlex::query::QueryField::Collection
                | binlex::query::QueryField::Architecture
        ),
        binlex::query::QueryExpr::Not(inner) => search_requires_full_exact_scan(inner),
        binlex::query::QueryExpr::And(lhs, rhs) | binlex::query::QueryExpr::Or(lhs, rhs) => {
            search_requires_full_exact_scan(lhs) || search_requires_full_exact_scan(rhs)
        }
    }
}

fn collect_exact_search_candidates(
    state: &AppState,
    plan: &crate::query::SearchPlan,
    sha256: &str,
    page_size: usize,
) -> Result<Vec<SearchResult>, String> {
    let page_size = page_size.max(64);
    let mut page = 0usize;
    let mut results = Vec::new();
    loop {
        let chunk = state
            .index
            .exact_search_page(
                &plan.corpora,
                sha256,
                Some(&plan.collections),
                &plan.architectures,
                page,
                page_size,
            )
            .map_err(|error| error.to_string())?;
        let chunk_len = chunk.len();
        if chunk_len == 0 {
            break;
        }
        results.extend(chunk);
        if chunk_len < page_size {
            break;
        }
        page = page.saturating_add(1);
    }
    Ok(results)
}

fn collect_scan_search_candidates(
    state: &AppState,
    plan: &crate::query::SearchPlan,
    page_size: usize,
) -> Result<Vec<SearchResult>, String> {
    let page_size = page_size.max(64);
    let mut page = 0usize;
    let mut results = Vec::new();
    loop {
        let offset = page.saturating_mul(page_size);
        let chunk = state
            .index
            .scan_search_page(
                &plan.corpora,
                Some(&plan.collections),
                &plan.architectures,
                offset,
                page_size,
            )
            .map_err(|error| error.to_string())?;
        let chunk_len = chunk.len();
        if chunk_len == 0 {
            break;
        }
        results.extend(chunk);
        if chunk_len < page_size {
            break;
        }
        page = page.saturating_add(1);
    }
    Ok(results)
}

fn evaluate_stream(
    state: &AppState,
    plan: &StreamPlan,
    candidate_limit: usize,
    limit: usize,
    page: usize,
) -> Result<(ExecutedStream, Option<String>), String> {
    match plan {
        StreamPlan::Search(plan) => Ok((
            ExecutedStream::Search {
                results: collect_search_candidates(state, plan, candidate_limit, limit, page)?,
                side: match plan.side {
                    QuerySide::Lhs => RowSide::Lhs,
                    QuerySide::Rhs => RowSide::Rhs,
                },
            },
            None,
        )),
        StreamPlan::Compare {
            left,
            right,
            direction,
        } => {
            let (left_stream, left_warning) =
                evaluate_stream(state, left, candidate_limit, limit, page)?;
            let (right_stream, right_warning) =
                evaluate_stream(state, right, candidate_limit, limit, page)?;
            let warning = left_warning.or(right_warning);
            let left_results = expect_search_stream(left_stream, "left compare operand")?;
            let right_results = expect_search_stream(right_stream, "right compare operand")?;
            let pairs = match direction {
                CompareDirection::BestPerLeft => {
                    build_best_pairs_per_left(&left_results, &right_results, state.ui.compare.limit)
                }
                CompareDirection::BestPerRight => build_best_pairs_per_right(
                    &left_results,
                    &right_results,
                    state.ui.compare.limit,
                ),
            };
            Ok((ExecutedStream::Compare { pairs }, warning))
        }
        StreamPlan::Pipe { input, op } => {
            let (stream, warning) = evaluate_stream(state, input, candidate_limit, limit, page)?;
            apply_stream_op(stream, op, warning, state.ui.compare.ascending_limit, state)
        }
    }
}

fn expect_search_stream(stream: ExecutedStream, label: &str) -> Result<Vec<SearchResult>, String> {
    match stream {
        ExecutedStream::Search { results, .. } => Ok(results),
        ExecutedStream::Compare { .. } => Err(format!("{label} must resolve to a search stream")),
    }
}

fn apply_stream_op(
    stream: ExecutedStream,
    op: &StreamOp,
    warning: Option<String>,
    ascending_limit: usize,
    state: &AppState,
) -> Result<(ExecutedStream, Option<String>), String> {
    match (stream, op) {
        (ExecutedStream::Compare { mut pairs }, StreamOp::ScoreFilter(raw)) => {
            pairs.retain(|pair| query_score_matches(raw, pair.score));
            Ok((ExecutedStream::Compare { pairs }, warning))
        }
        (ExecutedStream::Search { mut results, side }, StreamOp::ScoreFilter(raw)) => {
            results.retain(|result| query_score_matches(raw, result.score()));
            Ok((ExecutedStream::Search { results, side }, warning))
        }
        (ExecutedStream::Compare { mut pairs }, StreamOp::Limit(limit)) => {
            pairs.truncate(*limit);
            Ok((ExecutedStream::Compare { pairs }, warning))
        }
        (ExecutedStream::Search { mut results, side }, StreamOp::Limit(limit)) => {
            results.truncate(*limit);
            Ok((ExecutedStream::Search { results, side }, warning))
        }
        (
            ExecutedStream::Compare { mut pairs },
            StreamOp::Ascending(crate::query::SortKey::Score),
        ) => {
            if pairs.len() > ascending_limit {
                return Err(format!(
                    "ascending:score requires at most {} compare results; refine the query or use limit:<n>",
                    ascending_limit
                ));
            }
            pairs.sort_by(|lhs, rhs| lhs.score.total_cmp(&rhs.score));
            Ok((ExecutedStream::Compare { pairs }, warning))
        }
        (
            ExecutedStream::Compare { mut pairs },
            StreamOp::Descending(crate::query::SortKey::Score),
        ) => {
            pairs.sort_by(|lhs, rhs| rhs.score.total_cmp(&lhs.score));
            Ok((ExecutedStream::Compare { pairs }, warning))
        }
        (ExecutedStream::Compare { .. }, StreamOp::Ascending(key))
        | (ExecutedStream::Compare { .. }, StreamOp::Descending(key)) => Err(format!(
            "{} sorting is only valid on search streams; compare streams support only score",
            sort_key_name(*key)
        )),
        (ExecutedStream::Compare { pairs }, StreamOp::Drop(QuerySide::Lhs)) => Ok((
            ExecutedStream::Search {
                results: pairs
                    .into_iter()
                    .map(|pair| pair.rhs.with_score(pair.score))
                    .collect(),
                side: RowSide::Rhs,
            },
            warning,
        )),
        (ExecutedStream::Compare { pairs }, StreamOp::Drop(QuerySide::Rhs)) => Ok((
            ExecutedStream::Search {
                results: pairs
                    .into_iter()
                    .map(|pair| pair.lhs.with_score(pair.score))
                    .collect(),
                side: RowSide::Lhs,
            },
            warning,
        )),
        (ExecutedStream::Search { mut results, side }, StreamOp::SearchFilter(query)) => {
            let analysis = query.analyze().map_err(|error| error.to_string())?;
            results.retain(|result| search_expr_matches(result, query.expr(), &analysis.root));
            Ok((ExecutedStream::Search { results, side }, warning))
        }
        (ExecutedStream::Search { results, side }, StreamOp::Expand(target)) => Ok((
            ExecutedStream::Search {
                results: expand_search_results(state, results, *target)?,
                side,
            },
            warning,
        )),
        (ExecutedStream::Search { mut results, side }, StreamOp::Ascending(key)) => {
            if results.len() > ascending_limit {
                return Err(format!(
                    "ascending:{} requires at most {} results; refine the query or use limit:<n>",
                    sort_key_name(*key),
                    ascending_limit
                ));
            }
            sort_search_results(&mut results, *key, true);
            Ok((ExecutedStream::Search { results, side }, warning))
        }
        (ExecutedStream::Search { mut results, side }, StreamOp::Descending(key)) => {
            if results.len() > ascending_limit {
                return Err(format!(
                    "descending:{} requires at most {} results; refine the query or use limit:<n>",
                    sort_key_name(*key),
                    ascending_limit
                ));
            }
            sort_search_results(&mut results, *key, false);
            Ok((ExecutedStream::Search { results, side }, warning))
        }
        (ExecutedStream::Search { .. }, StreamOp::Drop(_)) => {
            Err("drop:lhs and drop:rhs require a compare result stream".to_string())
        }
        (ExecutedStream::Compare { .. }, StreamOp::Expand(_)) => {
            Err("expand requires a search result stream".to_string())
        }
        (ExecutedStream::Compare { .. }, StreamOp::SearchFilter(_)) => {
            Err("search filters can only run after drop:lhs or drop:rhs".to_string())
        }
    }
}

fn sort_key_name(key: crate::query::SortKey) -> &'static str {
    match key {
        crate::query::SortKey::Score => "score",
        crate::query::SortKey::Size => "size",
        crate::query::SortKey::Embeddings => "embeddings",
        crate::query::SortKey::Address => "address",
        crate::query::SortKey::Timestamp => "timestamp",
        crate::query::SortKey::CyclomaticComplexity => "cyclomatic_complexity",
        crate::query::SortKey::AverageInstructionsPerBlock => "average_instructions_per_block",
        crate::query::SortKey::NumberOfInstructions => "number_of_instructions",
        crate::query::SortKey::NumberOfBlocks => "number_of_blocks",
        crate::query::SortKey::Markov => "markov",
        crate::query::SortKey::Entropy => "entropy",
        crate::query::SortKey::ChromosomeEntropy => "chromosome.entropy",
    }
}

fn sort_search_results(results: &mut [SearchResult], key: crate::query::SortKey, ascending: bool) {
    results.sort_by(|lhs, rhs| compare_search_results(lhs, rhs, key, ascending));
}

fn compare_search_results(
    lhs: &SearchResult,
    rhs: &SearchResult,
    key: crate::query::SortKey,
    ascending: bool,
) -> std::cmp::Ordering {
    let primary = match key {
        crate::query::SortKey::Score => {
            compare_optional_f32(Some(lhs.score()), Some(rhs.score()), ascending)
        }
        crate::query::SortKey::Size => lhs.size().cmp(&rhs.size()),
        crate::query::SortKey::Embeddings => lhs.embeddings().cmp(&rhs.embeddings()),
        crate::query::SortKey::Address => lhs.address().cmp(&rhs.address()),
        crate::query::SortKey::Timestamp => lhs.timestamp().cmp(&rhs.timestamp()),
        crate::query::SortKey::CyclomaticComplexity => compare_optional_u64(
            lhs.cyclomatic_complexity(),
            rhs.cyclomatic_complexity(),
            ascending,
        ),
        crate::query::SortKey::AverageInstructionsPerBlock => compare_optional_f64(
            lhs.average_instructions_per_block(),
            rhs.average_instructions_per_block(),
            ascending,
        ),
        crate::query::SortKey::NumberOfInstructions => compare_optional_u64(
            lhs.number_of_instructions(),
            rhs.number_of_instructions(),
            ascending,
        ),
        crate::query::SortKey::NumberOfBlocks => {
            compare_optional_u64(lhs.number_of_blocks(), rhs.number_of_blocks(), ascending)
        }
        crate::query::SortKey::Markov => {
            compare_optional_f64(lhs.markov(), rhs.markov(), ascending)
        }
        crate::query::SortKey::Entropy => {
            compare_optional_f64(lhs.entropy(), rhs.entropy(), ascending)
        }
        crate::query::SortKey::ChromosomeEntropy => compare_optional_f64(
            lhs.chromosome_entropy(),
            rhs.chromosome_entropy(),
            ascending,
        ),
    };
    if primary != std::cmp::Ordering::Equal {
        return primary;
    }
    let score_tiebreak = lhs.score().total_cmp(&rhs.score());
    if score_tiebreak != std::cmp::Ordering::Equal {
        return if ascending {
            score_tiebreak
        } else {
            score_tiebreak.reverse()
        };
    }
    let address_tiebreak = lhs.address().cmp(&rhs.address());
    if address_tiebreak != std::cmp::Ordering::Equal {
        return address_tiebreak;
    }
    lhs.object_id().cmp(rhs.object_id())
}

fn compare_optional_u64(lhs: Option<u64>, rhs: Option<u64>, ascending: bool) -> std::cmp::Ordering {
    match (lhs, rhs) {
        (Some(lhs), Some(rhs)) => {
            let order = lhs.cmp(&rhs);
            if ascending { order } else { order.reverse() }
        }
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    }
}

fn compare_optional_f64(lhs: Option<f64>, rhs: Option<f64>, ascending: bool) -> std::cmp::Ordering {
    match (lhs, rhs) {
        (Some(lhs), Some(rhs)) => {
            let order = lhs.total_cmp(&rhs);
            if ascending { order } else { order.reverse() }
        }
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    }
}

fn compare_optional_f32(lhs: Option<f32>, rhs: Option<f32>, ascending: bool) -> std::cmp::Ordering {
    match (lhs, rhs) {
        (Some(lhs), Some(rhs)) => {
            let order = lhs.total_cmp(&rhs);
            if ascending { order } else { order.reverse() }
        }
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    }
}

fn expand_search_results(
    state: &AppState,
    results: Vec<SearchResult>,
    target: ExpandTarget,
) -> Result<Vec<SearchResult>, String> {
    let mut expanded = Vec::<SearchResult>::new();
    for result in results {
        let child_collection = match (result.collection(), target) {
            (Collection::Function, ExpandTarget::Blocks) => Some(Collection::Block),
            (Collection::Function, ExpandTarget::Instructions) => Some(Collection::Instruction),
            (Collection::Block, ExpandTarget::Instructions) => Some(Collection::Instruction),
            _ => None,
        };
        let Some(child_collection) = child_collection else {
            continue;
        };
        let children = state
            .index
            .result_children(&result, child_collection)
            .map_err(|error| error.to_string())?;
        expanded.extend(
            children
                .into_iter()
                .map(|child| child.with_score(result.score())),
        );
    }
    Ok(expanded)
}

fn build_best_pairs_per_left(
    lhs: &[SearchResult],
    rhs: &[SearchResult],
    compare_limit: usize,
) -> Vec<ComparePair> {
    let mut pairs = Vec::new();
    for lhs_result in lhs.iter().take(compare_limit) {
        let Some((rhs_result, score)) = best_match(lhs_result, rhs) else {
            continue;
        };
        pairs.push(ComparePair {
            lhs: lhs_result.clone(),
            rhs: rhs_result.clone(),
            score,
        });
    }
    pairs.sort_by(|lhs, rhs| rhs.score.total_cmp(&lhs.score));
    pairs
}

fn build_best_pairs_per_right(
    lhs: &[SearchResult],
    rhs: &[SearchResult],
    compare_limit: usize,
) -> Vec<ComparePair> {
    let mut pairs = Vec::new();
    for rhs_result in rhs.iter().take(compare_limit) {
        let Some((lhs_result, score)) = best_match(rhs_result, lhs) else {
            continue;
        };
        pairs.push(ComparePair {
            lhs: lhs_result.clone(),
            rhs: rhs_result.clone(),
            score,
        });
    }
    pairs.sort_by(|lhs, rhs| rhs.score.total_cmp(&lhs.score));
    pairs
}

fn best_match<'a>(
    anchor: &SearchResult,
    candidates: &'a [SearchResult],
) -> Option<(&'a SearchResult, f32)> {
    let vector = anchor.vector();
    if vector.is_empty() {
        return None;
    }
    candidates
        .iter()
        .filter_map(|candidate| {
            if candidate.vector().is_empty() || candidate.vector().len() != vector.len() {
                return None;
            }
            Some((candidate, cosine(vector, candidate.vector())))
        })
        .max_by(|lhs, rhs| lhs.1.total_cmp(&rhs.1))
}
