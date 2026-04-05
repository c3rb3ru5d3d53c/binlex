fn bearer_api_key(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?.trim();
    let token = value.strip_prefix("Bearer ")?.trim();
    if token.is_empty() {
        return None;
    }
    Some(token.to_string())
}

fn temporary_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get("Token")?.to_str().ok()?.trim();
    if value.is_empty() {
        return None;
    }
    Some(value.to_string())
}

fn staging_key_for_request(
    state: &AppState,
    path: &str,
    headers: &HeaderMap,
) -> Result<String, AppError> {
    if state.route_token_enabled(path) {
        return temporary_token(headers)
            .ok_or_else(|| AppError::unauthorized("missing or invalid temporary token"));
    }
    Ok(temporary_token(headers).unwrap_or_else(|| "__default__".to_string()))
}

fn username_for_request(state: &AppState, headers: &HeaderMap) -> Result<String, AppError> {
    let Some(api_key) = bearer_api_key(headers) else {
        return Ok("anonymous".to_string());
    };
    let user = state
        .database
        .auth_user(&api_key)
        .map_err(|error| AppError::unauthorized(error.to_string()))?;
    Ok(user
        .map(|user| user.username)
        .unwrap_or_else(|| "anonymous".to_string()))
}

async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    let path = request.uri().path().to_string();
    if state.route_auth_enabled(&path) {
        let api_key = bearer_api_key(request.headers())
            .ok_or_else(|| AppError::unauthorized("missing or invalid bearer api key"))?;
        let user = state
            .database
            .auth_user(&api_key)
            .map_err(|error| AppError::unauthorized(error.to_string()))?;
        let Some(user) = user else {
            return Err(AppError::unauthorized("invalid api key"));
        };
        let allowed_roles = state.route_auth_roles(&path);
        if !allowed_roles.is_empty() && !allowed_roles.iter().any(|role| role == &user.role) {
            return Err(AppError::forbidden("role is not allowed for this endpoint"));
        }
    }
    if state.route_token_enabled(&path) {
        let token = temporary_token(request.headers())
            .ok_or_else(|| AppError::unauthorized("missing or invalid temporary token"))?;
        let authorized = state
            .database
            .token_check(&token)
            .map_err(|error| AppError::unauthorized(error.to_string()))?;
        if !authorized {
            return Err(AppError::unauthorized("invalid or expired temporary token"));
        }
    }
    Ok(next.run(request).await)
}

#[utoipa::path(
    get,
    path = "/api/v1/version",
    tag = "System",
    responses((status = 200, description = "Current binlex version.", body = VersionResponse))
)]
async fn version_api() -> Json<VersionResponse> {
    Json(VersionResponse {
        version: binlex::VERSION.to_string(),
    })
}

#[utoipa::path(
    post,
    path = "/api/v1/token",
    tag = "Tokens",
    request_body = TokenCreateRequest,
    responses((status = 200, description = "Created a temporary token.", body = TokenCreateResponse))
)]
async fn create_token_api(
    State(state): State<Arc<AppState>>,
    Json(_request): Json<TokenCreateRequest>,
) -> Result<Json<TokenCreateResponse>, AppError> {
    let database = state.database.clone();
    let ttl_seconds = state.ui.token.ttl_seconds;
    let response = task::spawn_blocking(move || {
        let (record, plaintext) = database
            .token_create(ttl_seconds)
            .map_err(|error| AppError::new(error.to_string()))?;
        Ok::<TokenCreateResponse, AppError>(TokenCreateResponse {
            token: plaintext,
            expires: record.expires,
        })
    })
    .await
    .map_err(|error| AppError::new(error.to_string()))??;
    Ok(Json(response))
}

#[utoipa::path(
    post,
    path = "/api/v1/token/clear",
    tag = "Tokens",
    request_body = TokenClearRequest,
    responses((status = 200, description = "Cleared a temporary token.", body = TokenActionResponse))
)]
async fn clear_token_api(
    State(state): State<Arc<AppState>>,
    Json(request): Json<TokenClearRequest>,
) -> Result<Json<TokenActionResponse>, AppError> {
    let database = state.database.clone();
    task::spawn_blocking(move || {
        let disabled = database
            .token_disable_value(&request.token)
            .map_err(|error| AppError::new(error.to_string()))?;
        if !disabled {
            return Err(AppError::new("temporary token not found"));
        }
        Ok::<(), AppError>(())
    })
    .await
    .map_err(|error| AppError::new(error.to_string()))??;
    Ok(Json(TokenActionResponse { ok: true }))
}

fn role_response(role: binlex::databases::RoleRecord) -> AuthRoleResponse {
    AuthRoleResponse {
        name: role.name,
        timestamp: role.timestamp,
    }
}

fn user_response(user: binlex::databases::UserRecord) -> AuthUserResponse {
    AuthUserResponse {
        username: user.username,
        role: user.role,
        enabled: user.enabled,
        reserved: user.reserved,
        timestamp: user.timestamp,
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/role/create",
    tag = "Auth",
    security(("bearer_auth" = [])),
    request_body = AuthRoleCreateRequest,
    responses((status = 200, description = "Created a role.", body = AuthRoleResponse))
)]
async fn auth_role_create_api(
    State(state): State<Arc<AppState>>,
    Json(request): Json<AuthRoleCreateRequest>,
) -> Result<Json<AuthRoleResponse>, AppError> {
    let database = state.database.clone();
    let response = task::spawn_blocking(move || {
        database
            .role_create(&request.name, None)
            .map(role_response)
            .map_err(|error| AppError::new(error.to_string()))
    })
    .await
    .map_err(|error| AppError::new(error.to_string()))??;
    Ok(Json(response))
}

#[utoipa::path(
    get,
    path = "/api/v1/auth/role",
    tag = "Auth",
    security(("bearer_auth" = [])),
    params(AuthRoleGetParams),
    responses((status = 200, description = "Fetched one role.", body = AuthRoleResponse))
)]
async fn auth_role_get_api(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AuthRoleGetParams>,
) -> Result<Json<AuthRoleResponse>, AppError> {
    let database = state.database.clone();
    let response = task::spawn_blocking(move || {
        database
            .role_get(&params.name)
            .map_err(|error| AppError::new(error.to_string()))?
            .map(role_response)
            .ok_or_else(|| AppError::new("role not found"))
    })
    .await
    .map_err(|error| AppError::new(error.to_string()))??;
    Ok(Json(response))
}

#[utoipa::path(
    get,
    path = "/api/v1/auth/roles/search",
    tag = "Auth",
    security(("bearer_auth" = [])),
    params(AuthSearchParams),
    responses((status = 200, description = "Search roles.", body = AuthRoleSearchResponse))
)]
async fn auth_roles_search_api(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AuthSearchParams>,
) -> Result<Json<AuthRoleSearchResponse>, AppError> {
    let database = state.database.clone();
    let response = task::spawn_blocking(move || {
        let page = database
            .role_search(&params.q, params.page.max(1), params.limit.max(1))
            .map_err(|error| AppError::new(error.to_string()))?;
        Ok::<AuthRoleSearchResponse, AppError>(AuthRoleSearchResponse {
            items: page.items.into_iter().map(role_response).collect(),
            page: page.page,
            limit: page.page_size,
            has_next: page.has_next,
        })
    })
    .await
    .map_err(|error| AppError::new(error.to_string()))??;
    Ok(Json(response))
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/role/delete",
    tag = "Auth",
    security(("bearer_auth" = [])),
    request_body = AuthRoleDeleteRequest,
    responses((status = 200, description = "Deleted a role.", body = TokenActionResponse))
)]
async fn auth_role_delete_api(
    State(state): State<Arc<AppState>>,
    Json(request): Json<AuthRoleDeleteRequest>,
) -> Result<Json<TokenActionResponse>, AppError> {
    let database = state.database.clone();
    task::spawn_blocking(move || {
        let deleted = database
            .role_delete(&request.name)
            .map_err(|error| AppError::new(error.to_string()))?;
        if !deleted {
            return Err(AppError::new("role not found"));
        }
        Ok::<(), AppError>(())
    })
    .await
    .map_err(|error| AppError::new(error.to_string()))??;
    Ok(Json(TokenActionResponse { ok: true }))
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/user/create",
    tag = "Auth",
    security(("bearer_auth" = [])),
    request_body = AuthUserCreateRequest,
    responses((status = 200, description = "Created a user and API key.", body = AuthUserCreateResponse))
)]
async fn auth_user_create_api(
    State(state): State<Arc<AppState>>,
    Json(request): Json<AuthUserCreateRequest>,
) -> Result<Json<AuthUserCreateResponse>, AppError> {
    let database = state.database.clone();
    let response = task::spawn_blocking(move || {
        let timestamp = Utc::now().to_rfc3339();
        let username = request.username;
        let role = request.role.unwrap_or_else(|| "user".to_string());
        let (user, api_key) = database
            .user_create(&username, &role, Some(&timestamp))
            .map_err(|error| AppError::new(error.to_string()))?;
        Ok::<AuthUserCreateResponse, AppError>(AuthUserCreateResponse {
            user: user_response(user),
            api_key,
        })
    })
    .await
    .map_err(|error| AppError::new(error.to_string()))??;
    Ok(Json(response))
}

#[utoipa::path(
    get,
    path = "/api/v1/auth/user",
    tag = "Auth",
    security(("bearer_auth" = [])),
    params(AuthUserGetParams),
    responses((status = 200, description = "Fetched one user.", body = AuthUserResponse))
)]
async fn auth_user_get_api(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AuthUserGetParams>,
) -> Result<Json<AuthUserResponse>, AppError> {
    let database = state.database.clone();
    let response = task::spawn_blocking(move || {
        database
            .user_get(&params.username)
            .map_err(|error| AppError::new(error.to_string()))?
            .map(user_response)
            .ok_or_else(|| AppError::new("user not found"))
    })
    .await
    .map_err(|error| AppError::new(error.to_string()))??;
    Ok(Json(response))
}

#[utoipa::path(
    get,
    path = "/api/v1/auth/users/search",
    tag = "Auth",
    security(("bearer_auth" = [])),
    params(AuthSearchParams),
    responses((status = 200, description = "Search users.", body = AuthUserSearchResponse))
)]
async fn auth_users_search_api(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AuthSearchParams>,
) -> Result<Json<AuthUserSearchResponse>, AppError> {
    let database = state.database.clone();
    let response = task::spawn_blocking(move || {
        let page = database
            .user_search(&params.q, params.page.max(1), params.limit.max(1))
            .map_err(|error| AppError::new(error.to_string()))?;
        Ok::<AuthUserSearchResponse, AppError>(AuthUserSearchResponse {
            items: page.items.into_iter().map(user_response).collect(),
            page: page.page,
            limit: page.page_size,
            has_next: page.has_next,
        })
    })
    .await
    .map_err(|error| AppError::new(error.to_string()))??;
    Ok(Json(response))
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/user/disable",
    tag = "Auth",
    security(("bearer_auth" = [])),
    request_body = AuthUserNameRequest,
    responses((status = 200, description = "Disabled a user.", body = TokenActionResponse))
)]
async fn auth_user_disable_api(
    State(state): State<Arc<AppState>>,
    Json(request): Json<AuthUserNameRequest>,
) -> Result<Json<TokenActionResponse>, AppError> {
    let database = state.database.clone();
    task::spawn_blocking(move || {
        database
            .user_disable(&request.username)
            .map_err(|error| AppError::new(error.to_string()))?;
        Ok::<(), AppError>(())
    })
    .await
    .map_err(|error| AppError::new(error.to_string()))??;
    Ok(Json(TokenActionResponse { ok: true }))
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/user/enable",
    tag = "Auth",
    security(("bearer_auth" = [])),
    request_body = AuthUserNameRequest,
    responses((status = 200, description = "Enabled a user.", body = TokenActionResponse))
)]
async fn auth_user_enable_api(
    State(state): State<Arc<AppState>>,
    Json(request): Json<AuthUserNameRequest>,
) -> Result<Json<TokenActionResponse>, AppError> {
    let database = state.database.clone();
    task::spawn_blocking(move || {
        database
            .user_enable(&request.username)
            .map_err(|error| AppError::new(error.to_string()))?;
        Ok::<(), AppError>(())
    })
    .await
    .map_err(|error| AppError::new(error.to_string()))??;
    Ok(Json(TokenActionResponse { ok: true }))
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/user/reset",
    tag = "Auth",
    security(("bearer_auth" = [])),
    request_body = AuthUserNameRequest,
    responses((status = 200, description = "Reset a user API key.", body = AuthUserResetResponse))
)]
async fn auth_user_reset_api(
    State(state): State<Arc<AppState>>,
    Json(request): Json<AuthUserNameRequest>,
) -> Result<Json<AuthUserResetResponse>, AppError> {
    let database = state.database.clone();
    let response = task::spawn_blocking(move || {
        let api_key = database
            .user_reset(&request.username, None)
            .map_err(|error| AppError::new(error.to_string()))?;
        Ok::<AuthUserResetResponse, AppError>(AuthUserResetResponse {
            username: request.username,
            api_key,
        })
    })
    .await
    .map_err(|error| AppError::new(error.to_string()))??;
    Ok(Json(response))
}
