#[utoipa::path(
    get,
    path = "/api/v1/projects/search",
    tag = "Projects",
    params(ProjectsSearchParams),
    responses(
        (status = 200, description = "Projects assigned to a sample.", body = ProjectsResponse),
        (status = 400, description = "Invalid request.", body = ApiErrorResponse)
    )
)]
async fn project_search_api(
    State(state): State<Arc<AppState>>,
    Extension(request_id): Extension<RequestId>,
    Query(params): Query<ProjectsSearchParams>,
) -> Result<Json<ProjectsResponse>, AppError> {
    if !is_sha256(params.sha256.trim()) {
        return Err(AppError::with_request_id(
            "invalid sha256",
            request_id.to_string(),
        ));
    }
    if let Some(username) = params.username.as_deref()
        && username.len() > state.ui.api.projects.max_query_length
    {
        return Err(AppError::with_request_id(
            "username filter is too long",
            request_id.to_string(),
        ));
    }
    if let Some(project_sha256) = params.project_sha256.as_deref()
        && project_sha256.len() > state.ui.api.projects.max_query_length
    {
        return Err(AppError::with_request_id(
            "project sha256 filter is too long",
            request_id.to_string(),
        ));
    }
    let page = params.page.unwrap_or(default_page()).max(1);
    let limit = params
        .limit
        .unwrap_or(state.ui.api.projects.default_page_size)
        .clamp(1, state.ui.api.projects.max_page_size.max(1));
    let state_for_query = state.clone();
    let request_id_for_query = request_id.to_string();
    let sample_sha256 = params.sha256.trim().to_string();
    let response_sha256 = sample_sha256.clone();
    let page_data = task::spawn_blocking(move || {
        state_for_query
            .database
            .project_search(&binlex::databases::ProjectSearchParams {
                sample_sha256: sample_sha256.clone(),
                username: params.username.clone(),
                tool: params.tool.clone(),
                project_sha256: params.project_sha256.clone(),
                page,
                page_size: limit,
            })
            .map_err(|error| {
                AppError::with_request_id(error.to_string(), request_id_for_query.clone())
            })
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))??;
    Ok(Json(ProjectsResponse {
        sha256: response_sha256,
        projects: page_data
            .items
            .into_iter()
            .map(build_project_summary_response)
            .collect(),
        page: page_data.page,
        limit: page_data.page_size,
        total_results: page_data.total_results,
        has_next: page_data.has_next,
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/samples/search",
    tag = "Projects",
    params(SamplesSearchParams),
    responses(
        (status = 200, description = "Search sample SHA256 values.", body = SamplesSearchResponse),
        (status = 400, description = "Invalid request.", body = ApiErrorResponse)
    )
)]
async fn sample_sha256_search_api(
    State(state): State<Arc<AppState>>,
    Extension(request_id): Extension<RequestId>,
    Query(params): Query<SamplesSearchParams>,
) -> Result<Json<SamplesSearchResponse>, AppError> {
    let q = params.q.unwrap_or_default();
    if q.len() > state.ui.api.projects.max_query_length {
        return Err(AppError::with_request_id(
            "sample search query is too long",
            request_id.to_string(),
        ));
    }
    let page = params.page.unwrap_or(default_page()).max(1);
    let limit = params
        .limit
        .unwrap_or(state.ui.api.projects.default_page_size)
        .clamp(1, state.ui.api.projects.max_page_size.max(1));
    let database = state.database.clone();
    let request_id_for_query = request_id.to_string();
    let query = q.clone();
    let result = task::spawn_blocking(move || {
        database
            .sample_sha256_search(&query, page, limit)
            .map_err(|error| AppError::with_request_id(error.to_string(), request_id_for_query))
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))??;
    Ok(Json(SamplesSearchResponse {
        samples: result.items.into_iter().map(|item| item.sha256).collect(),
        page: result.page,
        limit: result.page_size,
        total_results: result.total_results,
        has_next: result.has_next,
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/projects/{project_sha256}/samples/search",
    tag = "Projects",
    params(ProjectPathParams, ProjectAssignmentsSearchParams),
    responses(
        (status = 200, description = "Samples assigned to a project.", body = ProjectAssignedSamplesResponse),
        (status = 400, description = "Invalid request.", body = ApiErrorResponse)
    )
)]
async fn project_assignments_search_api(
    State(state): State<Arc<AppState>>,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<ProjectPathParams>,
    Query(params): Query<ProjectAssignmentsSearchParams>,
) -> Result<Json<ProjectAssignedSamplesResponse>, AppError> {
    if !is_sha256(path.project_sha256.trim()) {
        return Err(AppError::with_request_id(
            "invalid project sha256",
            request_id.to_string(),
        ));
    }
    if let Some(sample_sha256) = params.sample_sha256.as_deref()
        && sample_sha256.len() > state.ui.api.projects.max_query_length
    {
        return Err(AppError::with_request_id(
            "sample sha256 filter is too long",
            request_id.to_string(),
        ));
    }
    let page = params.page.unwrap_or(default_page()).max(1);
    let limit = params
        .limit
        .unwrap_or(state.ui.api.projects.default_page_size)
        .clamp(1, state.ui.api.projects.max_page_size.max(1));
    let state_for_query = state.clone();
    let request_id_for_query = request_id.to_string();
    let project_sha256 = path.project_sha256.trim().to_string();
    let response_project_sha256 = project_sha256.clone();
    let sample_filter = params.sample_sha256.clone();
    let page_data = task::spawn_blocking(move || {
        state_for_query
            .database
            .project_assignment_search(&project_sha256, sample_filter.as_deref(), page, limit)
            .map_err(|error| {
                AppError::with_request_id(error.to_string(), request_id_for_query.clone())
            })
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))??;
    Ok(Json(ProjectAssignedSamplesResponse {
        project_sha256: response_project_sha256,
        samples: page_data
            .items
            .into_iter()
            .map(build_project_assigned_sample_response)
            .collect(),
        page: page_data.page,
        limit: page_data.page_size,
        total_results: page_data.total_results,
        has_next: page_data.has_next,
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/projects/{project_sha256}/samples",
    tag = "Projects",
    params(ProjectPathParams),
    request_body = ProjectAssignmentCreateRequest,
    responses(
        (status = 200, description = "Assignment created.", body = ActionResponse),
        (status = 400, description = "Invalid request.", body = ApiErrorResponse)
    )
)]
async fn project_assignment_create_api(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<ProjectPathParams>,
    Json(request): Json<ProjectAssignmentCreateRequest>,
) -> Result<Json<ActionResponse>, AppError> {
    let project_sha256 = path.project_sha256.trim().to_string();
    let sample_sha256 = request.sample_sha256.trim().to_string();
    if !is_sha256(&project_sha256) || !is_sha256(&sample_sha256) {
        return Err(AppError::with_request_id(
            "invalid sha256",
            request_id.to_string(),
        ));
    }
    let username = username_for_request(state.as_ref(), &headers)?;
    ensure_sample_exists(state.as_ref(), &sample_sha256, &request_id.to_string()).await?;
    let request_id_for_create = request_id.to_string();
    let database = state.database.clone();
    let sample_state = request
        .sample_state
        .clone()
        .unwrap_or_else(|| "analyzed".to_string());
    task::spawn_blocking(move || {
        database
            .project_assignment_put(
                &project_sha256,
                &sample_sha256,
                &sample_state,
                &username,
                None,
            )
            .map_err(|error| AppError::with_request_id(error.to_string(), request_id_for_create))
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))??;
    Ok(Json(ActionResponse { ok: true }))
}

#[utoipa::path(
    delete,
    path = "/api/v1/projects/{project_sha256}/samples/{sample_sha256}",
    tag = "Projects",
    params(ProjectSamplePathParams),
    responses(
        (status = 200, description = "Assignment removed.", body = ActionResponse),
        (status = 400, description = "Invalid request.", body = ApiErrorResponse)
    )
)]
async fn project_assignment_delete_api(
    State(state): State<Arc<AppState>>,
    Extension(request_id): Extension<RequestId>,
    Path((project_sha256, sample_sha256)): Path<(String, String)>,
) -> Result<Json<ActionResponse>, AppError> {
    if !is_sha256(project_sha256.trim()) || !is_sha256(sample_sha256.trim()) {
        return Err(AppError::with_request_id(
            "invalid sha256",
            request_id.to_string(),
        ));
    }
    let request_id_for_delete = request_id.to_string();
    let database = state.database.clone();
    task::spawn_blocking(move || {
        database
            .project_assignment_delete(&project_sha256, &sample_sha256)
            .map_err(|error| AppError::with_request_id(error.to_string(), request_id_for_delete))
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))??;
    Ok(Json(ActionResponse { ok: true }))
}

#[utoipa::path(
    post,
    path = "/api/v1/projects",
    tag = "Projects",
    request_body(content = UploadSampleRequestDoc, content_type = "multipart/form-data"),
    responses(
        (status = 200, description = "Project uploaded.", body = ProjectUploadResponse)
    )
)]
async fn project_upload_api(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    mut multipart: Multipart,
) -> Result<Json<ProjectUploadResponse>, AppError> {
    if !state.ui.upload.project_files.enabled {
        return Ok(Json(ProjectUploadResponse {
            ok: false,
            project_sha256: None,
            error: Some("project uploads are disabled".to_string()),
        }));
    }
    let username = username_for_request(state.as_ref(), &headers)?;
    let mut filename = None::<String>;
    let mut bytes = Vec::new();
    let mut assigned_sha256 = Vec::<String>::new();
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?
    {
        let name = field.name().unwrap_or_default().to_string();
        match name.as_str() {
            "data" => {
                filename = field.file_name().map(ToOwned::to_owned);
                bytes = field
                    .bytes()
                    .await
                    .map_err(|error| {
                        AppError::with_request_id(error.to_string(), request_id.to_string())
                    })?
                    .to_vec();
            }
            "sha256" => {
                let value = field.text().await.unwrap_or_default();
                if !value.trim().is_empty() {
                    assigned_sha256.push(value);
                }
            }
            _ => {}
        }
    }
    if bytes.is_empty() {
        return Ok(Json(ProjectUploadResponse {
            ok: false,
            project_sha256: None,
            error: Some("no project file was provided".to_string()),
        }));
    }
    if bytes.len() > state.ui.upload.project_files.max_bytes {
        return Ok(Json(ProjectUploadResponse {
            ok: false,
            project_sha256: None,
            error: Some(format!(
                "project exceeds max size of {} bytes",
                state.ui.upload.project_files.max_bytes
            )),
        }));
    }
    let original_filename = filename.unwrap_or_else(|| "project.bin".to_string());
    let tool = match detect_project_tool(&original_filename) {
        Some(value) => value.to_string(),
        None => {
            return Ok(Json(ProjectUploadResponse {
                ok: false,
                project_sha256: None,
                error: Some("project type could not be detected from the file".to_string()),
            }));
        }
    };
    let extension = original_filename
        .rsplit('.')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if !project_tool_extensions(&tool).contains(&extension.as_str()) {
        return Ok(Json(ProjectUploadResponse {
            ok: false,
            project_sha256: None,
            error: Some("project file type is not supported".to_string()),
        }));
    }
    for sample_sha256 in &assigned_sha256 {
        if !is_sha256(sample_sha256.trim()) {
            return Ok(Json(ProjectUploadResponse {
                ok: false,
                project_sha256: None,
                error: Some("one or more assigned sample hashes are invalid".to_string()),
            }));
        }
        ensure_sample_exists(state.as_ref(), sample_sha256.trim(), &request_id.to_string()).await?;
    }

    let state_for_upload = state.clone();
    let request_id_for_upload = request_id.to_string();
    let response = task::spawn_blocking(move || {
        persist_project_upload(
            state_for_upload.as_ref(),
            &tool,
            &original_filename,
            &bytes,
            &assigned_sha256,
            &username,
        )
        .map_err(|error| AppError::with_request_id(error.to_string(), request_id_for_upload))
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))??;
    Ok(Json(response))
}

#[utoipa::path(
    delete,
    path = "/api/v1/projects/{project_sha256}",
    tag = "Projects",
    params(("project_sha256" = String, Path, description = "Project SHA256")),
    responses(
        (status = 200, description = "Project deleted.", body = ActionResponse),
        (status = 400, description = "Invalid request.", body = ApiErrorResponse)
    )
)]
async fn delete_project_api(
    State(state): State<Arc<AppState>>,
    Extension(request_id): Extension<RequestId>,
    Path(project_sha256): Path<String>,
) -> Result<Json<ActionResponse>, AppError> {
    if !is_sha256(project_sha256.trim()) {
        return Err(AppError::with_request_id(
            "invalid project sha256",
            request_id.to_string(),
        ));
    }
    let database = state.database.clone();
    let request_id_for_delete = request_id.to_string();
    task::spawn_blocking(move || {
        database
            .project_delete(project_sha256.trim())
            .map_err(|error| AppError::with_request_id(error.to_string(), request_id_for_delete))
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))??;
    Ok(Json(ActionResponse { ok: true }))
}

#[utoipa::path(
    get,
    path = "/api/v1/download/project/{project_sha256}",
    tag = "Download",
    params(DownloadProjectPathParams),
    responses(
        (status = 200, description = "Raw project artifact bytes.", content_type = "application/octet-stream", body = String),
        (status = 400, description = "Invalid request.", body = ApiErrorResponse)
    )
)]
async fn download_project_api(
    State(state): State<Arc<AppState>>,
    Extension(request_id): Extension<RequestId>,
    Path(params): Path<DownloadProjectPathParams>,
) -> Result<impl IntoResponse, AppError> {
    if !state.ui.download.project_files.enabled {
        return Err(AppError::with_request_id(
            "project downloads are disabled",
            request_id.to_string(),
        ));
    }
    if !is_sha256(params.project_sha256.trim()) {
        return Err(AppError::with_request_id(
            "invalid project sha256",
            request_id.to_string(),
        ));
    }
    let state_for_download = state.clone();
    let project_sha256 = params.project_sha256.clone();
    let request_id_for_download = request_id.to_string();
    let (filename, content_type, payload) = task::spawn_blocking(move || {
        let record = state_for_download
            .database
            .project_get(&project_sha256)
            .map_err(|error| AppError::with_request_id(error.to_string(), request_id_for_download.clone()))?
            .ok_or_else(|| AppError::with_request_id("project not found", request_id_for_download.clone()))?;
        if record.is_deleted {
            return Err(AppError::with_request_id(
                "project not found",
                request_id_for_download.clone(),
            ));
        }
        let bytes = state_for_download
            .index
            .project_get(&record.storage_key)
            .map_err(|error| AppError::with_request_id(error.to_string(), request_id_for_download.clone()))?;
        if bytes.len() > state_for_download.ui.download.project_files.max_bytes {
            return Err(AppError::with_request_id(
                format!(
                    "project exceeds max download size of {} bytes",
                    state_for_download.ui.download.project_files.max_bytes
                ),
                request_id_for_download.clone(),
            ));
        }
        Ok((record.original_filename, record.content_type, bytes))
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))??;
    Ok(download_response(&content_type, filename, payload))
}

fn build_project_summary_response(record: binlex::databases::ProjectRecord) -> ProjectSummaryResponse {
    ProjectSummaryResponse {
        project_sha256: record.project_sha256,
        tool: record.tool,
        original_filename: record.original_filename,
        size_bytes: record.size_bytes,
        content_type: record.content_type,
        container_format: record.container_format,
        uploaded_by: MetadataUserResponse {
            username: record.uploaded_by,
            profile_picture: None,
        },
        uploaded_timestamp: record.uploaded_timestamp,
    }
}

fn build_project_assigned_sample_response(
    record: binlex::databases::ProjectAssignmentRecord,
) -> ProjectAssignedSampleResponse {
    ProjectAssignedSampleResponse {
        sample_sha256: record.sample_sha256,
        sample_state: record.sample_state,
        assigned_by: MetadataUserResponse {
            username: record.assigned_by,
            profile_picture: None,
        },
        assigned_timestamp: record.assigned_timestamp,
    }
}

async fn ensure_sample_exists(
    state: &AppState,
    sample_sha256: &str,
    request_id: &str,
) -> Result<(), AppError> {
    let index = state.index.clone();
    let database = state.database.clone();
    let sample_sha256 = sample_sha256.to_string();
    let request_id = request_id.to_string();
    let request_id_for_task = request_id.clone();
    task::spawn_blocking(move || {
        if database
            .sample_status_get(&sample_sha256)
            .map_err(|error| AppError::with_request_id(error.to_string(), request_id_for_task.to_string()))?
            .is_some()
        {
            return Ok(());
        }
        index
            .sample_get(&sample_sha256)
            .map(|_| ())
            .map_err(|_| AppError::with_request_id("sample not found", request_id_for_task.to_string()))
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?
}

fn persist_project_upload(
    state: &AppState,
    tool: &str,
    original_filename: &str,
    bytes: &[u8],
    assigned_sha256: &[String],
    username: &str,
) -> Result<ProjectUploadResponse, AppError> {
    let project_sha256_digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    let project_sha256 = binlex::hex::encode(project_sha256_digest.as_ref());
    state
        .index
        .project_put(&project_sha256, bytes)
        .map_err(|error| AppError::new(error.to_string()))?;
    let timestamp = Utc::now().to_rfc3339();
    state
        .database
        .project_put(&binlex::databases::ProjectRecord {
            project_sha256: project_sha256.clone(),
            tool: tool.to_string(),
            original_filename: original_filename.to_string(),
            storage_key: project_sha256.clone(),
            size_bytes: bytes.len() as u64,
            content_type: content_type_for_filename(original_filename).to_string(),
            container_format: original_filename
                .rsplit('.')
                .next()
                .unwrap_or_default()
                .to_ascii_lowercase(),
            visibility: "public".to_string(),
            uploaded_by: username.to_string(),
            uploaded_timestamp: timestamp.clone(),
            updated_timestamp: timestamp.clone(),
            is_deleted: false,
        })
        .map_err(|error| AppError::new(error.to_string()))?;
    for sample_sha256 in assigned_sha256 {
        let sample_state = state
            .database
            .sample_status_get(sample_sha256)
            .ok()
            .flatten()
            .map(|record| record.status.as_str().to_string())
            .unwrap_or_else(|| "stored".to_string());
        state
            .database
            .project_assignment_put(&project_sha256, sample_sha256, &sample_state, username, Some(&timestamp))
            .map_err(|error| AppError::new(error.to_string()))?;
    }
    Ok(ProjectUploadResponse {
        ok: true,
        project_sha256: Some(project_sha256),
        error: None,
    })
}
