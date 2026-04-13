#[utoipa::path(
    get,
    path = "/api/v1/graph",
    tag = "Graph",
    params(GraphParams),
    responses(
        (status = 200, description = "Full graph for a single indexed sample.", body = serde_json::Value),
        (status = 400, description = "Invalid request.", body = ApiErrorResponse)
    )
)]
async fn graph_api(
    State(state): State<Arc<AppState>>,
    Extension(request_id): Extension<RequestId>,
    Query(params): Query<GraphParams>,
) -> Result<Json<GraphSnapshot>, AppError> {
    let sha256 = params.sha256.trim().to_string();
    if !is_sha256(&sha256) {
        return Err(AppError::with_request_id(
            "invalid sha256",
            request_id.to_string(),
        ));
    }
    let state_for_graph = state.clone();
    let sha256_for_graph = sha256.clone();
    let graph = task::spawn_blocking(move || {
        state_for_graph
            .index
            .graph_by_sha256(&sha256_for_graph)
            .map_err(|error| AppError::new(error.to_string()))
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?;

    info!("graph request_id={} sha256={}", request_id, sha256);
    Ok(Json(graph.snapshot()))
}

#[utoipa::path(
    get,
    path = "/api/v1/download/sample",
    tag = "Download",
    params(DownloadSampleParams),
    responses(
        (status = 200, description = "Password-protected ZIP containing a single sample.", content_type = "application/zip", body = String),
        (status = 400, description = "Invalid request.", body = ApiErrorResponse)
    )
)]
async fn download_sample(
    State(state): State<Arc<AppState>>,
    Extension(request_id): Extension<RequestId>,
    Query(params): Query<DownloadSampleParams>,
) -> Result<impl IntoResponse, AppError> {
    if !state.ui.download.sample.enabled {
        return Err(AppError::with_request_id(
            "sample downloads are disabled",
            request_id.to_string(),
        ));
    }
    let password = state.ui.download.samples.password.trim().to_string();
    if password.is_empty() {
        return Err(AppError::with_request_id(
            "sample downloads are enabled but no password is configured",
            request_id.to_string(),
        ));
    }
    if !is_sha256(params.sha256.trim()) {
        return Err(AppError::with_request_id(
            "invalid sha256",
            request_id.to_string(),
        ));
    }

    let sha256 = params.sha256.trim().to_string();
    let state_for_download = state.clone();
    let sha256_for_download = sha256.clone();
    let password_for_download = password.clone();
    let request_id_for_download = request_id.to_string();
    let payload = task::spawn_blocking(move || {
        let bytes = state_for_download
            .index
            .sample_get(&sha256_for_download)
            .map_err(|error| {
                AppError::with_request_id(error.to_string(), request_id_for_download.clone())
            })?;
        if bytes.len() > state_for_download.ui.download.sample.max_bytes {
            return Err(AppError::new(format!(
                "sample exceeds max download size of {} bytes",
                state_for_download.ui.download.sample.max_bytes
            )));
        }
        create_encrypted_sample_zip(&sha256_for_download, &bytes, &password_for_download)
            .map_err(|error| AppError::new(error.to_string()))
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?;

    info!(
        "sample download request_id={} sha256={}",
        request_id, sha256
    );
    Ok(download_response(
        "application/zip",
        format!("{}.zip", sha256),
        payload,
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/download/json",
    tag = "Download",
    params(DownloadJsonParams),
    responses(
        (status = 200, description = "Pretty JSON for a single indexed entity.", content_type = "application/json", body = serde_json::Value),
        (status = 400, description = "Invalid request.", body = ApiErrorResponse)
    )
)]
async fn download_json(
    State(state): State<Arc<AppState>>,
    Extension(request_id): Extension<RequestId>,
    Query(params): Query<DownloadJsonParams>,
) -> Result<impl IntoResponse, AppError> {
    let collection = parse_collection(&params.collection)
        .ok_or_else(|| AppError::with_request_id("invalid collection", request_id.to_string()))?;
    let state_for_download = state.clone();
    let corpus = params.corpus.clone();
    let sha256 = params.sha256.clone();
    let address = params.address;
    let payload = task::spawn_blocking(move || {
        let json = entity_json_for_download(
            state_for_download.as_ref(),
            &corpus,
            &sha256,
            collection,
            address,
        )
        .ok_or_else(|| AppError::new("entity json is unavailable"))?;
        let payload =
            serde_json::to_vec_pretty(&json).map_err(|error| AppError::new(error.to_string()))?;
        if payload.len() > state_for_download.ui.download.json.max_bytes {
            return Err(AppError::new(format!(
                "json exceeds max download size of {} bytes",
                state_for_download.ui.download.json.max_bytes
            )));
        }
        Ok(payload)
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?;

    info!(
        "json download request_id={} corpus={} sha256={} collection={} address={:#x}",
        request_id, params.corpus, params.sha256, params.collection, params.address
    );
    Ok(download_response(
        "application/json",
        format!(
            "{}-{}-0x{:x}.json",
            collection.as_str(),
            params.sha256,
            params.address
        ),
        payload,
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/download/samples",
    tag = "Download",
    params(DownloadSamplesParams),
    responses(
        (status = 200, description = "Password-protected ZIP containing multiple samples.", content_type = "application/zip", body = String),
        (status = 400, description = "Invalid request.", body = ApiErrorResponse)
    )
)]
async fn download_samples(
    State(state): State<Arc<AppState>>,
    Extension(request_id): Extension<RequestId>,
    Query(params): Query<DownloadSamplesParams>,
) -> Result<impl IntoResponse, AppError> {
    if !state.ui.download.samples.enabled {
        return Err(AppError::with_request_id(
            "sample downloads are disabled",
            request_id.to_string(),
        ));
    }
    let password = state.ui.download.samples.password.trim().to_string();
    if password.is_empty() {
        return Err(AppError::with_request_id(
            "sample downloads are enabled but no password is configured",
            request_id.to_string(),
        ));
    }
    let hashes = unique_sha256_list(&params.sha256)
        .map_err(|error| AppError::with_request_id(error.message, request_id.to_string()))?;
    if hashes.is_empty() {
        return Err(AppError::with_request_id(
            "no sample hashes were provided",
            request_id.to_string(),
        ));
    }
    if hashes.len() > state.ui.download.samples.max_count {
        return Err(AppError::with_request_id(
            format!(
                "requested {} samples but max_count is {}",
                hashes.len(),
                state.ui.download.samples.max_count
            ),
            request_id.to_string(),
        ));
    }

    let state_for_download = state.clone();
    let password_for_download = password.clone();
    let hashes_for_download = hashes.clone();
    let payload = task::spawn_blocking(move || {
        let mut total_bytes = 0usize;
        for sha256 in &hashes_for_download {
            let sample = state_for_download
                .index
                .sample_get(sha256)
                .map_err(|error| AppError::new(error.to_string()))?;
            total_bytes = total_bytes.saturating_add(sample.len());
            if total_bytes > state_for_download.ui.download.samples.max_total_bytes {
                return Err(AppError::new(format!(
                    "sample batch exceeds max_total_bytes of {}",
                    state_for_download.ui.download.samples.max_total_bytes
                )));
            }
        }
        create_encrypted_samples_zip(
            &state_for_download.index,
            &hashes_for_download,
            &password_for_download,
        )
        .map_err(|error| AppError::new(error.to_string()))
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?;

    info!(
        "sample batch download request_id={} count={}",
        request_id,
        hashes.len()
    );
    Ok(download_response(
        "application/zip",
        "samples.zip".to_string(),
        payload,
    ))
}
fn entity_json_for_download(
    state: &AppState,
    corpus: &str,
    sha256: &str,
    entity: Collection,
    address: u64,
) -> Option<serde_json::Value> {
    let graph = state.index.sample_load(corpus, sha256).ok()?;
    match entity {
        Collection::Instruction => {
            serde_json::to_value(graph.get_instruction(address)?.process()).ok()
        }
        Collection::Block => serde_json::to_value(
            binlex::controlflow::Block::new(address, &graph)
                .ok()?
                .process(),
        )
        .ok(),
        Collection::Function => serde_json::to_value(
            binlex::controlflow::Function::new(address, &graph)
                .ok()?
                .process(),
        )
        .ok(),
    }
}

fn create_encrypted_sample_zip(
    sha256: &str,
    sample: &[u8],
    password: &str,
) -> Result<Vec<u8>, Error> {
    let cursor = Cursor::new(Vec::<u8>::new());
    let mut writer = ZipWriter::new(cursor);
    let options = FileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .unix_permissions(0o600)
        .with_deprecated_encryption(password.as_bytes());
    writer
        .start_file(format!("{}.bin", sha256), options)
        .map_err(|error| Error::other(error.to_string()))?;
    std::io::Write::write_all(&mut writer, sample).map_err(Error::other)?;
    let cursor = writer
        .finish()
        .map_err(|error| Error::other(error.to_string()))?;
    Ok(cursor.into_inner())
}

fn create_encrypted_samples_zip(
    index: &LocalIndex,
    hashes: &[String],
    password: &str,
) -> Result<Vec<u8>, Error> {
    let cursor = Cursor::new(Vec::<u8>::new());
    let mut writer = ZipWriter::new(cursor);
    let options = FileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .unix_permissions(0o600)
        .with_deprecated_encryption(password.as_bytes());
    for sha256 in hashes {
        let sample = index
            .sample_get(sha256)
            .map_err(|error| Error::other(error.to_string()))?;
        writer
            .start_file(format!("{}.bin", sha256), options)
            .map_err(|error| Error::other(error.to_string()))?;
        std::io::Write::write_all(&mut writer, &sample).map_err(Error::other)?;
    }
    let cursor = writer
        .finish()
        .map_err(|error| Error::other(error.to_string()))?;
    Ok(cursor.into_inner())
}

fn unique_sha256_list(values: &[String]) -> Result<Vec<String>, AppError> {
    let mut unique = std::collections::BTreeSet::new();
    for value in values {
        let trimmed = value.trim();
        if !is_sha256(trimmed) {
            return Err(AppError::new(format!("invalid sha256 {}", trimmed)));
        }
        unique.insert(trimmed.to_string());
    }
    Ok(unique.into_iter().collect())
}

fn download_response(content_type: &str, filename: String, payload: Vec<u8>) -> Response {
    let headers = [
        (
            header::CONTENT_TYPE,
            HeaderValue::from_str(content_type)
                .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
        ),
        (
            header::CONTENT_DISPOSITION,
            HeaderValue::from_str(&format!("attachment; filename=\"{}\"", filename))
                .unwrap_or_else(|_| HeaderValue::from_static("attachment")),
        ),
    ];
    (StatusCode::OK, headers, payload).into_response()
}
