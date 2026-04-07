const DEFAULT_COMMENT_PAGE_SIZE: usize = 20;
const MAX_COMMENT_PAGE_SIZE: usize = 50;

fn clamp_comment_page(value: Option<usize>) -> usize {
    value.unwrap_or(1).max(1)
}

fn clamp_comment_page_size(value: Option<usize>) -> usize {
    value
        .unwrap_or(DEFAULT_COMMENT_PAGE_SIZE)
        .clamp(1, MAX_COMMENT_PAGE_SIZE)
}

fn build_entity_comment_response(
    state: &AppState,
    record: &binlex::databases::EntityCommentRecord,
) -> EntityCommentResponse {
    EntityCommentResponse {
        id: record.id,
        sha256: record.sha256.clone(),
        collection: record.collection.as_str().to_string(),
        address: record.address,
        actor: metadata_actor_response(state, &record.username),
        timestamp: record.timestamp.clone(),
        body: record.comment.clone(),
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/comments",
    tag = "Comments",
    params(CollectionCommentsParams),
    responses(
        (status = 200, description = "Entity comments.", body = EntityCommentsResponse),
        (status = 400, description = "Invalid request.", body = ApiErrorResponse)
    )
)]
async fn get_entity_comments_api(
    State(state): State<Arc<AppState>>,
    Extension(request_id): Extension<RequestId>,
    Query(params): Query<CollectionCommentsParams>,
) -> Result<Json<EntityCommentsResponse>, AppError> {
    let collection = parse_collection(&params.collection)
        .ok_or_else(|| AppError::with_request_id("invalid collection", request_id.to_string()))?;
    let page = clamp_comment_page(params.page);
    let page_size = clamp_comment_page_size(params.page_size);
    let sha256 = params.sha256.clone();
    let address = params.address;
    let state_for_work = state.clone();
    let request_id_for_work = request_id.to_string();
    let response = task::spawn_blocking(move || {
        let page = state_for_work
            .index
            .entity_comment_list(&sha256, collection, address, page, page_size)
            .map_err(|error| {
                AppError::with_request_id(error.to_string(), request_id_for_work.clone())
            })?;
        Ok::<EntityCommentsResponse, AppError>(EntityCommentsResponse {
            sha256: sha256.clone(),
            collection: collection.as_str().to_string(),
            address,
            items: page
                .items
                .iter()
                .map(|item| build_entity_comment_response(state_for_work.as_ref(), item))
                .collect(),
            page: page.page,
            page_size: page.page_size,
            total_results: page.total_results,
            has_next: page.has_next,
        })
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))??;
    Ok(Json(response))
}

#[utoipa::path(
    post,
    path = "/api/v1/comments/add",
    tag = "Comments",
    security(("bearer_auth" = [])),
    request_body = EntityCommentCreateRequest,
    responses(
        (status = 200, description = "Created entity comment.", body = EntityCommentResponse),
        (status = 400, description = "Invalid request.", body = ApiErrorResponse)
    )
)]
async fn add_entity_comment_api(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestAuthContext>,
    Extension(request_id): Extension<RequestId>,
    Json(request): Json<EntityCommentCreateRequest>,
) -> Result<Json<EntityCommentResponse>, AppError> {
    let user = context.user.ok_or_else(|| {
        AppError::with_request_id("authentication required", request_id.to_string())
    })?;
    let collection = parse_collection(&request.collection)
        .ok_or_else(|| AppError::with_request_id("invalid collection", request_id.to_string()))?;
    let sha256 = request.sha256.clone();
    let address = request.address;
    let body = request.body.clone();
    let username = user.username.clone();
    let state_for_work = state.clone();
    let request_id_for_work = request_id.to_string();
    let response = task::spawn_blocking(move || {
        let created = state_for_work
            .index
            .entity_comment_add(&sha256, collection, address, &username, &body)
            .map_err(|error| {
                AppError::with_request_id(error.to_string(), request_id_for_work.clone())
            })?;
        Ok::<EntityCommentResponse, AppError>(build_entity_comment_response(
            state_for_work.as_ref(),
            &created,
        ))
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))??;
    Ok(Json(response))
}

#[utoipa::path(
    delete,
    path = "/api/v1/comments/{id}",
    tag = "Comments",
    security(("bearer_auth" = [])),
    params(
        ("id" = i64, Path, description = "Comment id")
    ),
    responses(
        (status = 200, description = "Deleted entity comment.", body = CommentActionResponse),
        (status = 400, description = "Invalid request.", body = ApiErrorResponse)
    )
)]
async fn delete_entity_comment_api(
    State(state): State<Arc<AppState>>,
    Extension(request_id): Extension<RequestId>,
    Path(id): Path<i64>,
) -> Result<Json<CommentActionResponse>, AppError> {
    let state_for_work = state.clone();
    let request_id_for_work = request_id.to_string();
    task::spawn_blocking(move || {
        let deleted = state_for_work
            .index
            .entity_comment_delete(id)
            .map_err(|error| {
                AppError::with_request_id(error.to_string(), request_id_for_work.clone())
            })?;
        if !deleted {
            return Err(AppError::with_request_id(
                "comment not found",
                request_id_for_work.clone(),
            ));
        }
        Ok::<CommentActionResponse, AppError>(CommentActionResponse { ok: true })
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?
    .map(Json)
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/comments",
    tag = "Comments",
    security(("bearer_auth" = [])),
    params(AdminCommentsSearchParams),
    responses(
        (status = 200, description = "Admin comment moderation search.", body = AdminCommentsSearchResponse),
        (status = 400, description = "Invalid request.", body = ApiErrorResponse)
    )
)]
async fn admin_comments_api(
    State(state): State<Arc<AppState>>,
    Extension(request_id): Extension<RequestId>,
    Query(params): Query<AdminCommentsSearchParams>,
) -> Result<Json<AdminCommentsSearchResponse>, AppError> {
    let page = clamp_comment_page(params.page);
    let page_size = clamp_comment_page_size(params.page_size);
    let query = params.q.clone();
    let state_for_work = state.clone();
    let request_id_for_work = request_id.to_string();
    let response = task::spawn_blocking(move || {
        let page = state_for_work
            .index
            .entity_comment_search(&query, page, page_size)
            .map_err(|error| {
                AppError::with_request_id(error.to_string(), request_id_for_work.clone())
            })?;
        Ok::<AdminCommentsSearchResponse, AppError>(AdminCommentsSearchResponse {
            items: page
                .items
                .iter()
                .map(|item| build_entity_comment_response(state_for_work.as_ref(), item))
                .collect(),
            page: page.page,
            page_size: page.page_size,
            total_results: page.total_results,
            has_next: page.has_next,
        })
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))??;
    Ok(Json(response))
}
