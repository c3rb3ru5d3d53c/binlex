fn metadata_actor_response(state: &AppState, username: &str) -> MetadataActorResponse {
    let normalized = username.trim();
    let (profile_picture, timestamp) = if normalized.is_empty() {
        (None, None)
    } else if let Some(user) = state.database.user_get(normalized).ok().flatten() {
        (user.profile_picture, Some(user.timestamp))
    } else {
        (None, None)
    };
    let profile_picture = if normalized.is_empty() {
        None
    } else {
        avatar_url_for_user(normalized, profile_picture.as_deref(), timestamp.as_deref())
    };
    MetadataActorResponse {
        username: normalized.to_string(),
        profile_picture,
    }
}

fn metadata_item_response(
    state: &AppState,
    name: &str,
    username: &str,
    timestamp: &str,
) -> MetadataItemResponse {
    MetadataItemResponse {
        name: name.to_string(),
        created_actor: metadata_actor_response(state, username),
        created_timestamp: timestamp.to_string(),
        assigned_actor: None,
        assigned_timestamp: None,
    }
}

fn metadata_assigned_item_response(
    state: &AppState,
    name: &str,
    created_username: &str,
    created_timestamp: &str,
    assigned_username: &str,
    assigned_timestamp: &str,
) -> MetadataItemResponse {
    MetadataItemResponse {
        name: name.to_string(),
        created_actor: metadata_actor_response(state, created_username),
        created_timestamp: created_timestamp.to_string(),
        assigned_actor: Some(metadata_actor_response(state, assigned_username)),
        assigned_timestamp: Some(assigned_timestamp.to_string()),
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/corpora/collection",
    tag = "Corpora",
    security(("bearer_auth" = [])),
    params(CollectionCorporaParams),
    responses((status = 200, description = "Collection corpora.", body = CorporaResponse))
)]
async fn get_collection_corpora_api(
    State(state): State<Arc<AppState>>,
    Extension(request_id): Extension<RequestId>,
    Query(params): Query<CollectionCorporaParams>,
) -> Result<Json<CorporaResponse>, AppError> {
    let collection = parse_collection(&params.collection)
        .ok_or_else(|| AppError::with_request_id("invalid collection", request_id.to_string()))?;
    let sha256 = params.sha256.clone();
    let architecture = params.architecture.clone();
    let address = params.address;
    let state_for_work = state.clone();
    let corpora = task::spawn_blocking(move || {
        state_for_work.index.collection_corpus_details_list(
            &sha256,
            collection,
            &architecture,
            address,
        )
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?;
    Ok(Json(CorporaResponse {
        sha256: params.sha256,
        collection: Some(params.collection),
        architecture: Some(params.architecture),
        address: Some(params.address),
        corpora: corpora
            .into_iter()
            .map(|item| {
                let created = state.database.corpus_get(&item.corpus).ok().flatten();
                metadata_assigned_item_response(
                    state.as_ref(),
                    &item.corpus,
                    created
                        .as_ref()
                        .map(|value| value.username.as_str())
                        .unwrap_or(""),
                    created
                        .as_ref()
                        .map(|value| value.timestamp.as_str())
                        .unwrap_or(""),
                    &item.username,
                    &item.timestamp,
                )
            })
            .collect(),
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/corpora/collection/add",
    tag = "Corpora",
    security(("bearer_auth" = [])),
    request_body = CollectionCorpusActionRequest,
    responses((status = 200, description = "Added a collection corpus.", body = TagsActionResponse))
)]
async fn add_collection_corpus_api(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestAuthContext>,
    Extension(request_id): Extension<RequestId>,
    Json(request): Json<CollectionCorpusActionRequest>,
) -> Result<Json<TagsActionResponse>, AppError> {
    let collection = parse_collection(&request.collection)
        .ok_or_else(|| AppError::with_request_id("invalid collection", request_id.to_string()))?;
    let username = context
        .user
        .as_ref()
        .map(|user| user.username.clone())
        .ok_or_else(|| AppError::unauthorized("authentication is required"))?;
    let state_for_work = state.clone();
    task::spawn_blocking(move || {
        state_for_work.index.collection_corpus_add(
            &request.sha256,
            collection,
            &request.architecture,
            request.address,
            &request.corpus,
            &username,
        )
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?;
    Ok(Json(TagsActionResponse { ok: true }))
}

#[utoipa::path(
    post,
    path = "/api/v1/corpora/collection/remove",
    tag = "Corpora",
    security(("bearer_auth" = [])),
    request_body = CollectionCorpusActionRequest,
    responses((status = 200, description = "Removed a collection corpus.", body = TagsActionResponse))
)]
async fn remove_collection_corpus_api(
    State(state): State<Arc<AppState>>,
    Extension(request_id): Extension<RequestId>,
    Json(request): Json<CollectionCorpusActionRequest>,
) -> Result<Json<TagsActionResponse>, AppError> {
    let collection = parse_collection(&request.collection)
        .ok_or_else(|| AppError::with_request_id("invalid collection", request_id.to_string()))?;
    let state_for_work = state.clone();
    task::spawn_blocking(move || {
        state_for_work.index.collection_corpus_remove(
            &request.sha256,
            collection,
            &request.architecture,
            request.address,
            &request.corpus,
        )
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?;
    Ok(Json(TagsActionResponse { ok: true }))
}

#[utoipa::path(
    get,
    path = "/api/v1/tags/sample",
    tag = "Tags",
    security(("bearer_auth" = [])),
    params(SampleTagsParams),
    responses((status = 200, description = "Sample tags.", body = TagsResponse))
)]
async fn get_sample_tags(
    State(state): State<Arc<AppState>>,
    Extension(request_id): Extension<RequestId>,
    Query(params): Query<SampleTagsParams>,
) -> Result<Json<TagsResponse>, AppError> {
    let sha256 = params.sha256.clone();
    let state_for_work = state.clone();
    let tags = task::spawn_blocking(move || state_for_work.index.sample_tag_list(&sha256))
        .await
        .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?
        .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?;
    Ok(Json(TagsResponse {
        sha256: params.sha256,
        collection: None,
        address: None,
        tags: tags
            .into_iter()
            .map(|tag| metadata_item_response(state.as_ref(), &tag, "", ""))
            .collect(),
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/tags/sample/add",
    tag = "Tags",
    security(("bearer_auth" = [])),
    request_body = SampleTagActionRequest,
    responses((status = 200, description = "Added a sample tag.", body = TagsActionResponse))
)]
async fn add_sample_tag(
    State(state): State<Arc<AppState>>,
    Extension(request_id): Extension<RequestId>,
    Json(request): Json<SampleTagActionRequest>,
) -> Result<Json<TagsActionResponse>, AppError> {
    let state_for_work = state.clone();
    task::spawn_blocking(move || {
        state_for_work
            .index
            .sample_tag_add(&request.sha256, &request.tag)
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?;
    Ok(Json(TagsActionResponse { ok: true }))
}

#[utoipa::path(
    post,
    path = "/api/v1/tags/sample/remove",
    tag = "Tags",
    security(("bearer_auth" = [])),
    request_body = SampleTagActionRequest,
    responses((status = 200, description = "Removed a sample tag.", body = TagsActionResponse))
)]
async fn remove_sample_tag(
    State(state): State<Arc<AppState>>,
    Extension(request_id): Extension<RequestId>,
    Json(request): Json<SampleTagActionRequest>,
) -> Result<Json<TagsActionResponse>, AppError> {
    let state_for_work = state.clone();
    task::spawn_blocking(move || {
        state_for_work
            .index
            .sample_tag_remove(&request.sha256, &request.tag)
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?;
    Ok(Json(TagsActionResponse { ok: true }))
}

#[utoipa::path(
    post,
    path = "/api/v1/tags/sample/replace",
    tag = "Tags",
    security(("bearer_auth" = [])),
    request_body = SampleTagsReplaceRequest,
    responses((status = 200, description = "Replaced sample tags.", body = TagsActionResponse))
)]
async fn replace_sample_tags(
    State(state): State<Arc<AppState>>,
    Extension(request_id): Extension<RequestId>,
    Json(request): Json<SampleTagsReplaceRequest>,
) -> Result<Json<TagsActionResponse>, AppError> {
    let state_for_work = state.clone();
    task::spawn_blocking(move || {
        state_for_work
            .index
            .sample_tag_replace(&request.sha256, &request.tags)
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?;
    Ok(Json(TagsActionResponse { ok: true }))
}

#[utoipa::path(
    get,
    path = "/api/v1/tags/collection",
    tag = "Tags",
    security(("bearer_auth" = [])),
    params(CollectionTagsParams),
    responses((status = 200, description = "Collection tags.", body = TagsResponse))
)]
async fn get_collection_tags(
    State(state): State<Arc<AppState>>,
    Extension(request_id): Extension<RequestId>,
    Query(params): Query<CollectionTagsParams>,
) -> Result<Json<TagsResponse>, AppError> {
    let collection = parse_collection(&params.collection)
        .ok_or_else(|| AppError::with_request_id("invalid collection", request_id.to_string()))?;
    let sha256 = params.sha256.clone();
    let address = params.address;
    let state_for_work = state.clone();
    let tags = task::spawn_blocking(move || {
        state_for_work
            .index
            .collection_tag_details_list(&sha256, collection, address)
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?;
    Ok(Json(TagsResponse {
        sha256: params.sha256,
        collection: Some(params.collection),
        address: Some(params.address),
        tags: tags
            .into_iter()
            .map(|item| {
                let created = state.database.tag_get(&item.tag).ok().flatten();
                metadata_assigned_item_response(
                    state.as_ref(),
                    &item.tag,
                    created
                        .as_ref()
                        .map(|value| value.username.as_str())
                        .unwrap_or(""),
                    created
                        .as_ref()
                        .map(|value| value.timestamp.as_str())
                        .unwrap_or(""),
                    &item.username,
                    &item.timestamp,
                )
            })
            .collect(),
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/tags/collection/add",
    tag = "Tags",
    security(("bearer_auth" = [])),
    request_body = CollectionTagActionRequest,
    responses((status = 200, description = "Added a collection tag.", body = TagsActionResponse))
)]
async fn add_collection_tag_api(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestAuthContext>,
    Extension(request_id): Extension<RequestId>,
    Json(request): Json<CollectionTagActionRequest>,
) -> Result<Json<TagsActionResponse>, AppError> {
    let collection = parse_collection(&request.collection)
        .ok_or_else(|| AppError::with_request_id("invalid collection", request_id.to_string()))?;
    let username = context
        .user
        .as_ref()
        .map(|user| user.username.clone())
        .ok_or_else(|| AppError::unauthorized("authentication is required"))?;
    let state_for_work = state.clone();
    task::spawn_blocking(move || {
        state_for_work.index.collection_tag_add(
            &request.sha256,
            collection,
            request.address,
            &request.tag,
            &username,
        )
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?;
    Ok(Json(TagsActionResponse { ok: true }))
}

#[utoipa::path(
    post,
    path = "/api/v1/tags/collection/remove",
    tag = "Tags",
    security(("bearer_auth" = [])),
    request_body = CollectionTagActionRequest,
    responses((status = 200, description = "Removed a collection tag.", body = TagsActionResponse))
)]
async fn remove_collection_tag_api(
    State(state): State<Arc<AppState>>,
    Extension(request_id): Extension<RequestId>,
    Json(request): Json<CollectionTagActionRequest>,
) -> Result<Json<TagsActionResponse>, AppError> {
    let collection = parse_collection(&request.collection)
        .ok_or_else(|| AppError::with_request_id("invalid collection", request_id.to_string()))?;
    let state_for_work = state.clone();
    task::spawn_blocking(move || {
        state_for_work.index.collection_tag_remove(
            &request.sha256,
            collection,
            request.address,
            &request.tag,
        )
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?;
    Ok(Json(TagsActionResponse { ok: true }))
}

#[utoipa::path(
    post,
    path = "/api/v1/tags/collection/replace",
    tag = "Tags",
    security(("bearer_auth" = [])),
    request_body = CollectionTagsReplaceRequest,
    responses((status = 200, description = "Replaced collection tags.", body = TagsActionResponse))
)]
async fn replace_collection_tags_api(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestAuthContext>,
    Extension(request_id): Extension<RequestId>,
    Json(request): Json<CollectionTagsReplaceRequest>,
) -> Result<Json<TagsActionResponse>, AppError> {
    let collection = parse_collection(&request.collection)
        .ok_or_else(|| AppError::with_request_id("invalid collection", request_id.to_string()))?;
    let username = context
        .user
        .as_ref()
        .map(|user| user.username.clone())
        .ok_or_else(|| AppError::unauthorized("authentication is required"))?;
    let state_for_work = state.clone();
    task::spawn_blocking(move || {
        state_for_work.index.collection_tag_replace(
            &request.sha256,
            collection,
            request.address,
            &request.tags,
            &username,
        )
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?;
    Ok(Json(TagsActionResponse { ok: true }))
}

#[utoipa::path(
    get,
    path = "/api/v1/tags/search",
    tag = "Tags",
    security(("bearer_auth" = [])),
    params(SearchTagsParams),
    responses((status = 200, description = "Tag search results.", body = TagsCatalogResponse))
)]
async fn search_tags_api(
    State(state): State<Arc<AppState>>,
    Extension(request_id): Extension<RequestId>,
    Query(params): Query<SearchTagsParams>,
) -> Result<Json<TagsCatalogResponse>, AppError> {
    let q = params.q.clone();
    let limit = params.limit.unwrap_or(64).clamp(1, 256);
    let state_for_work = state.clone();
    let results = task::spawn_blocking(move || state_for_work.database.tag_search(&q, limit))
        .await
        .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?
        .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?;
    Ok(Json(TagsCatalogResponse {
        tags: results
            .items
            .into_iter()
            .map(|item| {
                metadata_item_response(state.as_ref(), &item.tag, &item.username, &item.timestamp)
            })
            .collect(),
        total_results: results.total_results,
        has_next: results.has_next,
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/tags/add",
    tag = "Tags",
    security(("bearer_auth" = [])),
    request_body = TagActionRequest,
    responses((status = 200, description = "Added a tag.", body = TagsActionResponse))
)]
async fn add_tag_api(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestAuthContext>,
    Extension(request_id): Extension<RequestId>,
    Json(request): Json<TagActionRequest>,
) -> Result<Json<TagsActionResponse>, AppError> {
    let username = context
        .user
        .as_ref()
        .map(|user| user.username.clone())
        .ok_or_else(|| AppError::unauthorized("authentication is required"))?;
    let state_for_work = state.clone();
    task::spawn_blocking(move || {
        state_for_work
            .database
            .tag_add(&request.tag, None, Some(&username))
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?;
    Ok(Json(TagsActionResponse { ok: true }))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/tags/delete",
    tag = "Admin",
    security(("bearer_auth" = [])),
    request_body = TagActionRequest,
    responses((status = 200, description = "Deleted a tag globally.", body = TagsActionResponse))
)]
async fn admin_delete_tag_api(
    State(state): State<Arc<AppState>>,
    Extension(request_id): Extension<RequestId>,
    Json(request): Json<TagActionRequest>,
) -> Result<Json<TagsActionResponse>, AppError> {
    let tag = request.tag.trim().to_string();
    if tag.is_empty() {
        return Err(AppError::with_request_id(
            "tag must not be empty",
            request_id.to_string(),
        ));
    }
    let state_for_work = state.clone();
    task::spawn_blocking(move || {
        state_for_work
            .database
            .tag_delete_global(&tag)
            .map_err(|error| AppError::new(error.to_string()))
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))??;
    Ok(Json(TagsActionResponse { ok: true }))
}

#[utoipa::path(
    get,
    path = "/api/v1/tags/search/sample",
    tag = "Tags",
    params(SearchAssignedTagsParams),
    responses((status = 200, description = "Sample tag search results.", body = TagSearchResponse))
)]
async fn search_sample_tags_api(
    State(state): State<Arc<AppState>>,
    Extension(request_id): Extension<RequestId>,
    Query(params): Query<SearchAssignedTagsParams>,
) -> Result<Json<TagSearchResponse>, AppError> {
    let page = params.page.unwrap_or(1);
    let page_size = params.page_size.unwrap_or(50);
    let q = params.q.clone();
    let state_for_work = state.clone();
    let results =
        task::spawn_blocking(move || state_for_work.index.sample_tag_search(&q, page, page_size))
            .await
            .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?
            .map_err(|error| {
                AppError::with_request_id(error.to_string(), request_id.to_string())
            })?;
    Ok(Json(TagSearchResponse {
        items: results
            .items
            .into_iter()
            .map(|item| TagSearchItemResponse {
                sha256: item.sha256,
                tag: item.tag,
                timestamp: item.timestamp,
            })
            .collect(),
        page: results.page,
        page_size: results.page_size,
        has_next: results.has_next,
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/tags/search/collection",
    tag = "Tags",
    params(SearchCollectionTagsParams),
    responses((status = 200, description = "Collection tag search results.", body = CollectionTagSearchResponse))
)]
async fn search_collection_tags_api(
    State(state): State<Arc<AppState>>,
    Extension(request_id): Extension<RequestId>,
    Query(params): Query<SearchCollectionTagsParams>,
) -> Result<Json<CollectionTagSearchResponse>, AppError> {
    let collection = match params.collection.as_deref() {
        Some(value) => Some(parse_collection(value).ok_or_else(|| {
            AppError::with_request_id("invalid collection", request_id.to_string())
        })?),
        None => None,
    };
    let page = params.page.unwrap_or(1);
    let page_size = params.page_size.unwrap_or(50);
    let q = params.q.clone();
    let state_for_work = state.clone();
    let results = task::spawn_blocking(move || {
        state_for_work
            .index
            .collection_tag_search(&q, collection, page, page_size)
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?;
    Ok(Json(CollectionTagSearchResponse {
        items: results
            .items
            .into_iter()
            .map(|item| CollectionTagSearchItemResponse {
                sha256: item.sha256,
                collection: item.collection.to_string(),
                address: item.address,
                tag: item.tag,
                timestamp: item.timestamp,
            })
            .collect(),
        page: results.page,
        page_size: results.page_size,
        has_next: results.has_next,
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/symbols/collection",
    tag = "Symbols",
    security(("bearer_auth" = [])),
    params(CollectionSymbolsParams),
    responses((status = 200, description = "Collection symbols.", body = SymbolsResponse))
)]
async fn get_collection_symbols(
    State(state): State<Arc<AppState>>,
    Extension(request_id): Extension<RequestId>,
    Query(params): Query<CollectionSymbolsParams>,
) -> Result<Json<SymbolsResponse>, AppError> {
    let collection = parse_collection(&params.collection)
        .ok_or_else(|| AppError::with_request_id("invalid collection", request_id.to_string()))?;
    let sha256 = params.sha256.clone();
    let architecture = params.architecture.clone();
    let address = params.address;
    let state_for_work = state.clone();
    let symbols = task::spawn_blocking(move || {
        state_for_work
            .index
            .symbol_details_list(&sha256, collection, &architecture, address)
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?;
    Ok(Json(SymbolsResponse {
        sha256: params.sha256,
        collection: params.collection,
        architecture: params.architecture,
        address: params.address,
        symbols: symbols
            .into_iter()
            .map(|item| {
                let created = state.database.symbol_get(&item.name).ok().flatten();
                metadata_assigned_item_response(
                    state.as_ref(),
                    &item.name,
                    created
                        .as_ref()
                        .map(|value| value.username.as_str())
                        .unwrap_or(""),
                    created
                        .as_ref()
                        .map(|value| value.timestamp.as_str())
                        .unwrap_or(""),
                    &item.username,
                    &item.timestamp,
                )
            })
            .collect(),
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/symbols/collection/remove",
    tag = "Symbols",
    security(("bearer_auth" = [])),
    request_body = CollectionSymbolActionRequest,
    responses((status = 200, description = "Removed a collection symbol.", body = TagsActionResponse))
)]
async fn remove_collection_symbol_api(
    State(state): State<Arc<AppState>>,
    Extension(request_id): Extension<RequestId>,
    Json(request): Json<CollectionSymbolActionRequest>,
) -> Result<Json<TagsActionResponse>, AppError> {
    let collection = parse_collection(&request.collection)
        .ok_or_else(|| AppError::with_request_id("invalid collection", request_id.to_string()))?;
    let state_for_work = state.clone();
    task::spawn_blocking(move || {
        state_for_work.index.symbol_remove(
            &request.sha256,
            collection,
            request.address,
            &request.symbol,
        )
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?;
    Ok(Json(TagsActionResponse { ok: true }))
}

#[utoipa::path(
    get,
    path = "/api/v1/symbols/search",
    tag = "Symbols",
    security(("bearer_auth" = [])),
    params(SearchSymbolsParams),
    responses((status = 200, description = "Symbol search results.", body = SymbolsCatalogResponse))
)]
async fn search_symbols_api(
    State(state): State<Arc<AppState>>,
    Extension(request_id): Extension<RequestId>,
    Query(params): Query<SearchSymbolsParams>,
) -> Result<Json<SymbolsCatalogResponse>, AppError> {
    let q = params.q.clone();
    let limit = params.limit.unwrap_or(64).clamp(1, 256);
    let state_for_work = state.clone();
    let results = task::spawn_blocking(move || state_for_work.database.symbol_search(&q, limit))
        .await
        .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?
        .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?;
    Ok(Json(SymbolsCatalogResponse {
        symbols: results
            .items
            .into_iter()
            .map(|item| {
                metadata_item_response(
                    state.as_ref(),
                    &item.symbol,
                    &item.username,
                    &item.timestamp,
                )
            })
            .collect(),
        total_results: results.total_results,
        has_next: results.has_next,
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/symbols/add",
    tag = "Symbols",
    security(("bearer_auth" = [])),
    request_body = SymbolActionRequest,
    responses((status = 200, description = "Added a symbol.", body = TagsActionResponse))
)]
async fn add_symbol_api(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestAuthContext>,
    Extension(request_id): Extension<RequestId>,
    Json(request): Json<SymbolActionRequest>,
) -> Result<Json<TagsActionResponse>, AppError> {
    let username = context
        .user
        .as_ref()
        .map(|user| user.username.clone())
        .ok_or_else(|| AppError::unauthorized("authentication is required"))?;
    let state_for_work = state.clone();
    task::spawn_blocking(move || {
        state_for_work
            .database
            .symbol_add(&request.symbol, None, Some(&username))
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?;
    Ok(Json(TagsActionResponse { ok: true }))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/symbols/delete",
    tag = "Admin",
    security(("bearer_auth" = [])),
    request_body = SymbolActionRequest,
    responses((status = 200, description = "Deleted a symbol globally.", body = TagsActionResponse))
)]
async fn admin_delete_symbol_api(
    State(state): State<Arc<AppState>>,
    Extension(request_id): Extension<RequestId>,
    Json(request): Json<SymbolActionRequest>,
) -> Result<Json<TagsActionResponse>, AppError> {
    let symbol = request.symbol.trim().to_string();
    if symbol.is_empty() {
        return Err(AppError::with_request_id(
            "symbol must not be empty",
            request_id.to_string(),
        ));
    }
    let state_for_work = state.clone();
    task::spawn_blocking(move || {
        state_for_work
            .index
            .symbol_delete_global(&symbol)
            .map_err(|error| AppError::new(error.to_string()))
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))??;
    Ok(Json(TagsActionResponse { ok: true }))
}

#[utoipa::path(
    post,
    path = "/api/v1/symbols/collection/add",
    tag = "Symbols",
    security(("bearer_auth" = [])),
    request_body = CollectionSymbolActionRequest,
    responses((status = 200, description = "Added a collection symbol.", body = TagsActionResponse))
)]
async fn add_collection_symbol_api(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestAuthContext>,
    Extension(request_id): Extension<RequestId>,
    Json(request): Json<CollectionSymbolActionRequest>,
) -> Result<Json<TagsActionResponse>, AppError> {
    let collection = parse_collection(&request.collection)
        .ok_or_else(|| AppError::with_request_id("invalid collection", request_id.to_string()))?;
    let username = context
        .user
        .as_ref()
        .map(|user| user.username.clone())
        .ok_or_else(|| AppError::unauthorized("authentication is required"))?;
    let state_for_work = state.clone();
    task::spawn_blocking(move || {
        state_for_work.index.symbol_add(
            &request.sha256,
            collection,
            request.address,
            &request.symbol,
            &username,
        )
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?;
    Ok(Json(TagsActionResponse { ok: true }))
}

#[utoipa::path(
    post,
    path = "/api/v1/symbols/collection/replace",
    tag = "Symbols",
    security(("bearer_auth" = [])),
    request_body = CollectionSymbolsReplaceRequest,
    responses((status = 200, description = "Replaced collection symbols.", body = TagsActionResponse))
)]
async fn replace_collection_symbols_api(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestAuthContext>,
    Extension(request_id): Extension<RequestId>,
    Json(request): Json<CollectionSymbolsReplaceRequest>,
) -> Result<Json<TagsActionResponse>, AppError> {
    let collection = parse_collection(&request.collection)
        .ok_or_else(|| AppError::with_request_id("invalid collection", request_id.to_string()))?;
    let first = request.symbols.first().cloned().ok_or_else(|| {
        AppError::with_request_id("symbols must not be empty", request_id.to_string())
    })?;
    let username = context
        .user
        .as_ref()
        .map(|user| user.username.clone())
        .ok_or_else(|| AppError::unauthorized("authentication is required"))?;
    let state_for_work = state.clone();
    task::spawn_blocking(move || {
        state_for_work.index.symbol_replace(
            &request.sha256,
            collection,
            request.address,
            &first,
            &username,
        )
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?;
    Ok(Json(TagsActionResponse { ok: true }))
}
