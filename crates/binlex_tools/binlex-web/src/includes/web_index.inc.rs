fn normalize_request_corpora(values: &[String]) -> Vec<String> {
    let values = values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    if values.is_empty() {
        vec![DEFAULT_CORPUS.to_string()]
    } else {
        values
    }
}

fn parse_request_collections(values: &[String]) -> Result<Vec<Collection>, AppError> {
    if values.is_empty() {
        return Ok(Vec::new());
    }
    values
        .iter()
        .map(|value| parse_collection(value).ok_or_else(|| AppError::new("invalid collection")))
        .collect()
}

fn snapshot_from_value(value: Value) -> Result<GraphSnapshot, AppError> {
    serde_json::from_value(value).map_err(|error| AppError::new(error.to_string()))
}

fn selector_value<'a>(value: &'a Value, selector: &str) -> Option<&'a Value> {
    let mut current = value;
    for part in selector.split('.') {
        if part.is_empty() {
            return None;
        }
        let mut remainder = part;
        let key_end = remainder.find('[').unwrap_or(remainder.len());
        if key_end > 0 {
            current = current.get(&remainder[..key_end])?;
            remainder = &remainder[key_end..];
        }
        while !remainder.is_empty() {
            let after_open = remainder.strip_prefix('[')?;
            let close = after_open.find(']')?;
            let index = after_open[..close].parse::<usize>().ok()?;
            current = current.get(index)?;
            remainder = &after_open[close + 1..];
        }
    }
    Some(current)
}

fn selector_vector(value: &Value, selector: &str) -> Option<Vec<f32>> {
    let vector = selector_value(value, selector)?.as_array()?;
    vector
        .iter()
        .map(|value| value.as_f64().map(|item| item as f32))
        .collect()
}

fn configured_selector(state: &AppState) -> String {
    state.ui.index.local.selector.clone()
}

fn process_graph_snapshot(state: &AppState, snapshot: GraphSnapshot) -> Result<Graph, AppError> {
    state
        .client
        .process_snapshot(snapshot)
        .map_err(|error| AppError::new(error.to_string()))
}

fn selector_vector_or_error(value: &Value, selector: &str) -> Result<Vec<f32>, AppError> {
    selector_vector(value, selector)
        .ok_or_else(|| AppError::new("selector did not resolve to a vector"))
}

fn process_function_value(state: &AppState, value: Value) -> Result<FunctionJson, AppError> {
    let function =
        serde_json::from_value(value).map_err(|error| AppError::new(error.to_string()))?;
    state
        .client
        .process_function_json(function)
        .map_err(|error| AppError::new(error.to_string()))
}

fn process_block_value(state: &AppState, value: Value) -> Result<BlockJson, AppError> {
    let block = serde_json::from_value(value).map_err(|error| AppError::new(error.to_string()))?;
    state
        .client
        .process_block_json(block)
        .map_err(|error| AppError::new(error.to_string()))
}

fn process_instruction_value(state: &AppState, value: Value) -> Result<InstructionJson, AppError> {
    let instruction =
        serde_json::from_value(value).map_err(|error| AppError::new(error.to_string()))?;
    state
        .client
        .process_instruction_json(instruction)
        .map_err(|error| AppError::new(error.to_string()))
}

#[utoipa::path(
    post,
    path = "/api/v1/index/graph",
    tag = "Index",
    security(("bearer_auth" = [])),
    request_body = IndexGraphRequest,
    responses((status = 200, description = "Staged graph indexing.", body = IndexActionResponse))
)]
async fn stage_index_graph(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Json(request): Json<IndexGraphRequest>,
) -> Result<Json<IndexActionResponse>, AppError> {
    let state_for_work = state.clone();
    let request_id_for_error = request_id.to_string();
    let token = staging_key_for_request(&headers)?;
    let username = username_for_request(state.as_ref(), &headers)?;
    task::spawn_blocking(move || {
        let staged = state_for_work.staged_index(&token)?;
        let selector = configured_selector(state_for_work.as_ref());
        let snapshot = snapshot_from_value(request.graph)?;
        let processed = process_graph_snapshot(state_for_work.as_ref(), snapshot)?;
        let collections = parse_request_collections(&request.collections)?;
        let corpora = normalize_request_corpora(&request.corpora);
        if request.attributes.is_some() {
            return Err(AppError::new(
                "graph attributes are not supported by this endpoint yet",
            ));
        }
        staged
            .graph_many_as(
                &corpora,
                &request.sha256,
                &processed,
                &[],
                Some(&selector),
                if collections.is_empty() {
                    None
                } else {
                    Some(&collections)
                },
                &username,
            )
            .map_err(|error| AppError::new(error.to_string()))
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id_for_error))??;
    Ok(Json(IndexActionResponse { ok: true }))
}

#[utoipa::path(
    post,
    path = "/api/v1/index/function",
    tag = "Index",
    security(("bearer_auth" = [])),
    request_body = IndexFunctionRequest,
    responses((status = 200, description = "Staged function indexing.", body = IndexActionResponse))
)]
async fn stage_index_function(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Json(request): Json<IndexFunctionRequest>,
) -> Result<Json<IndexActionResponse>, AppError> {
    let token = staging_key_for_request(&headers)?;
    let username = username_for_request(state.as_ref(), &headers)?;
    let state_for_work = state.clone();
    task::spawn_blocking(move || {
        let staged = state_for_work.staged_index(&token)?;
        let selector = configured_selector(state_for_work.as_ref());
        let corpora = normalize_request_corpora(&request.corpora);
        let processed = process_function_value(state_for_work.as_ref(), request.function)?;
        let processed_value =
            serde_json::to_value(&processed).map_err(|error| AppError::new(error.to_string()))?;
        let vector = selector_vector_or_error(&processed_value, &selector)?;
        staged
            .function_json_many_as(
                &corpora,
                &processed,
                &vector,
                &request.sha256,
                &[],
                &username,
            )
            .map_err(|error| AppError::new(error.to_string()))
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))??;
    Ok(Json(IndexActionResponse { ok: true }))
}

#[utoipa::path(
    post,
    path = "/api/v1/index/block",
    tag = "Index",
    security(("bearer_auth" = [])),
    request_body = IndexBlockRequest,
    responses((status = 200, description = "Staged block indexing.", body = IndexActionResponse))
)]
async fn stage_index_block(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Json(request): Json<IndexBlockRequest>,
) -> Result<Json<IndexActionResponse>, AppError> {
    let token = staging_key_for_request(&headers)?;
    let username = username_for_request(state.as_ref(), &headers)?;
    let state_for_work = state.clone();
    task::spawn_blocking(move || {
        let staged = state_for_work.staged_index(&token)?;
        let selector = configured_selector(state_for_work.as_ref());
        let corpora = normalize_request_corpora(&request.corpora);
        let processed = process_block_value(state_for_work.as_ref(), request.block)?;
        let processed_value =
            serde_json::to_value(&processed).map_err(|error| AppError::new(error.to_string()))?;
        let vector = selector_vector_or_error(&processed_value, &selector)?;
        staged
            .block_json_many_as(
                &corpora,
                &processed,
                &vector,
                &request.sha256,
                &[],
                &username,
            )
            .map_err(|error| AppError::new(error.to_string()))
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))??;
    Ok(Json(IndexActionResponse { ok: true }))
}

#[utoipa::path(
    post,
    path = "/api/v1/index/instruction",
    tag = "Index",
    security(("bearer_auth" = [])),
    request_body = IndexInstructionRequest,
    responses((status = 200, description = "Staged instruction indexing.", body = IndexActionResponse))
)]
async fn stage_index_instruction(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Json(request): Json<IndexInstructionRequest>,
) -> Result<Json<IndexActionResponse>, AppError> {
    let token = staging_key_for_request(&headers)?;
    let username = username_for_request(state.as_ref(), &headers)?;
    let state_for_work = state.clone();
    task::spawn_blocking(move || {
        let staged = state_for_work.staged_index(&token)?;
        let selector = configured_selector(state_for_work.as_ref());
        let corpora = normalize_request_corpora(&request.corpora);
        let processed = process_instruction_value(state_for_work.as_ref(), request.instruction)?;
        let processed_value =
            serde_json::to_value(&processed).map_err(|error| AppError::new(error.to_string()))?;
        let vector = selector_vector_or_error(&processed_value, &selector)?;
        staged
            .instruction_json_many_as(
                &corpora,
                &processed,
                &vector,
                &request.sha256,
                &[],
                &username,
            )
            .map_err(|error| AppError::new(error.to_string()))
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))??;
    Ok(Json(IndexActionResponse { ok: true }))
}

#[utoipa::path(
    post,
    path = "/api/v1/index/commit",
    tag = "Index",
    security(("bearer_auth" = [])),
    request_body = IndexCommitRequest,
    responses((status = 200, description = "Committed staged indexing work.", body = IndexActionResponse))
)]
async fn commit_index(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Json(_request): Json<IndexCommitRequest>,
) -> Result<Json<IndexActionResponse>, AppError> {
    let token = staging_key_for_request(&headers)?;
    let state_for_work = state.clone();
    task::spawn_blocking(move || {
        let staged = state_for_work.remove_staged_index(&token)?;
        staged
            .commit()
            .map_err(|error| AppError::new(error.to_string()))
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))??;
    Ok(Json(IndexActionResponse { ok: true }))
}

#[utoipa::path(
    post,
    path = "/api/v1/index/clear",
    tag = "Index",
    security(("bearer_auth" = [])),
    request_body = IndexCommitRequest,
    responses((status = 200, description = "Cleared staged indexing work.", body = IndexActionResponse))
)]
async fn clear_index(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Json(_request): Json<IndexCommitRequest>,
) -> Result<Json<IndexActionResponse>, AppError> {
    let token = staging_key_for_request(&headers)?;
    let state_for_work = state.clone();
    task::spawn_blocking(move || {
        let staged = state_for_work.remove_staged_index(&token)?;
        staged.clear();
        Ok::<(), AppError>(())
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))??;
    Ok(Json(IndexActionResponse { ok: true }))
}
