#[utoipa::path(
    post,
    path = "/api/v1/index/sample",
    tag = "Index",
    request_body(content = UploadSampleRequestDoc, content_type = "multipart/form-data", description = "Upload a sample for analysis and indexing by binlex-server."),
    responses(
        (status = 200, description = "Upload result.", body = UploadResponse)
    )
)]
async fn upload(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    mut multipart: Multipart,
) -> Result<Json<UploadResponse>, AppError> {
    if !state.ui.upload.sample.enabled {
        return Ok(Json(UploadResponse {
            ok: false,
            sha256: None,
            error: Some(format!(
                "sample uploads are disabled. Request ID: {}",
                request_id
            )),
            stored: None,
        }));
    }
    let mut form = UploadForm::default();
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?
    {
        let name = field.name().unwrap_or_default().to_string();
        match name.as_str() {
            "data" => {
                form.filename = field.file_name().map(ToOwned::to_owned);
                form.bytes = field
                    .bytes()
                    .await
                    .map_err(|error| {
                        AppError::with_request_id(error.to_string(), request_id.to_string())
                    })?
                    .to_vec();
            }
            "format" => {
                let value = field.text().await.unwrap_or_default();
                if !value.trim().is_empty() {
                    form.format = Some(value);
                }
            }
            "architecture" => {
                let value = field.text().await.unwrap_or_default();
                if !value.trim().is_empty() {
                    form.architecture = Some(value);
                }
            }
            "mode" => {
                let value = field.text().await.unwrap_or_default();
                if !value.trim().is_empty() {
                    form.mode = Some(value);
                }
            }
            "corpus" => form.corpus.push(field.text().await.unwrap_or_default()),
            "tag" => form.tags.push(field.text().await.unwrap_or_default()),
            _ => {}
        }
    }
    if form.bytes.len() > state.ui.upload.sample.max_bytes {
        return Ok(Json(UploadResponse {
            ok: false,
            sha256: None,
            error: Some(format!(
                "upload exceeds max size of {} bytes. Request ID: {}",
                state.ui.upload.sample.max_bytes, request_id
            )),
            stored: None,
        }));
    }

    let state_for_upload = state.clone();
    let request_id_for_upload = request_id.to_string();
    let username = username_for_request(state.as_ref(), &headers)?;
    let result = task::spawn_blocking(move || {
        ingest_upload(
            state_for_upload.as_ref(),
            form,
            &request_id_for_upload,
            &username,
        )
    })
    .await
    .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?;

    Ok(Json(result))
}

#[utoipa::path(
    get,
    path = "/api/v1/index/status",
    tag = "Index",
    params(UploadStatusParams),
    responses(
        (status = 200, description = "Current upload analysis status.", body = UploadStatusResponse),
        (status = 400, description = "Invalid request.", body = ApiErrorResponse)
    )
)]
async fn upload_status(
    State(state): State<Arc<AppState>>,
    Extension(request_id): Extension<RequestId>,
    Query(params): Query<UploadStatusParams>,
) -> Result<Json<UploadStatusResponse>, AppError> {
    if !is_sha256(params.sha256.trim()) {
        return Err(AppError::with_request_id(
            "invalid sha256",
            request_id.to_string(),
        ));
    }
    let sha256 = params.sha256.trim().to_string();
    let database = state.database.clone();
    let request_id_for_status = request_id.to_string();
    let record = task::spawn_blocking(move || database.sample_status_get(&sha256))
        .await
        .map_err(|error| AppError::with_request_id(error.to_string(), request_id.to_string()))?
        .map_err(|error| {
            AppError::with_request_id(error.to_string(), request_id_for_status.clone())
        })?
        .ok_or_else(|| {
            AppError::with_request_id("sample status not found", request_id.to_string())
        })?;
    Ok(Json(UploadStatusResponse::from(record)))
}
const UPLOAD_INDEX_COMMIT_BATCH_SIZE: usize = 512;

fn index_selected_vectors(
    index: &LocalIndex,
    graph: &Graph,
    selected: &binlex::server::dto::AnalyzeSelectedVectors,
    corpora: &[String],
    sha256: &str,
    collections: &[Collection],
    username: &str,
) -> Result<usize, AppError> {
    let mut indexed = 0usize;
    let mut staged_since_commit = 0usize;
    for collection in collections {
        match collection {
            Collection::Function => {
                for function in graph.functions() {
                    let Some(vector) = selected.functions.get(&function.address) else {
                        continue;
                    };
                    let json = function.process();
                    index
                        .function_json_many_as(corpora, &json, vector, sha256, &[], username)
                        .map_err(|error| AppError::new(error.to_string()))?;
                    indexed += 1;
                    staged_since_commit += 1;
                    if staged_since_commit >= UPLOAD_INDEX_COMMIT_BATCH_SIZE {
                        index
                            .commit()
                            .map_err(|error| AppError::new(error.to_string()))?;
                        staged_since_commit = 0;
                    }
                }
            }
            Collection::Block => {
                for function in graph.functions() {
                    let function_markov = function.markov();
                    for block in function.blocks() {
                        let Some(vector) = selected.blocks.get(&block.address()) else {
                            continue;
                        };
                        let json = block.process();
                        index
                            .block_json_many_as_with_markov(
                                corpora,
                                &json,
                                vector,
                                sha256,
                                function_markov.get(&block.address()).copied(),
                                &[],
                                username,
                            )
                            .map_err(|error| AppError::new(error.to_string()))?;
                        indexed += 1;
                        staged_since_commit += 1;
                        if staged_since_commit >= UPLOAD_INDEX_COMMIT_BATCH_SIZE {
                            index
                                .commit()
                                .map_err(|error| AppError::new(error.to_string()))?;
                            staged_since_commit = 0;
                        }
                    }
                }
            }
            Collection::Instruction => {
                for instruction in graph.instructions() {
                    let Some(vector) = selected.instructions.get(&instruction.address) else {
                        continue;
                    };
                    let json = instruction.process();
                    index
                        .instruction_json_many_as(corpora, &json, vector, sha256, &[], username)
                        .map_err(|error| AppError::new(error.to_string()))?;
                    indexed += 1;
                    staged_since_commit += 1;
                    if staged_since_commit >= UPLOAD_INDEX_COMMIT_BATCH_SIZE {
                        index
                            .commit()
                            .map_err(|error| AppError::new(error.to_string()))?;
                        staged_since_commit = 0;
                    }
                }
            }
        }
    }
    if staged_since_commit > 0 {
        index
            .commit()
            .map_err(|error| AppError::new(error.to_string()))?;
    }
    Ok(indexed)
}

fn ingest_upload(
    state: &AppState,
    form: UploadForm,
    request_id: &str,
    username: &str,
) -> UploadResponse {
    if form.bytes.is_empty() {
        return UploadResponse {
            ok: false,
            sha256: None,
            error: Some("no data was provided".to_string()),
            stored: None,
        };
    }

    if matches!(form.mode.as_deref(), Some("store")) {
        let sha256 = match state.index.sample_put(&form.bytes) {
            Ok(sha256) => sha256,
            Err(error) => {
                return UploadResponse {
                    ok: false,
                    sha256: None,
                    error: Some(format!(
                        "failed to store sample: {} Request ID: {}",
                        error, request_id
                    )),
                    stored: None,
                };
            }
        };
        if let Err(error) = write_sample_status(
            state.database.as_ref(),
            &sha256,
            SampleStatus::Stored,
            None,
            Some(request_id),
        ) {
            return UploadResponse {
                ok: false,
                sha256: Some(sha256),
                error: Some(format!(
                    "failed to write stored sample status: {} Request ID: {}",
                    error, request_id
                )),
                stored: None,
            };
        }
        return UploadResponse {
            ok: true,
            sha256: Some(sha256),
            error: None,
            stored: Some(true),
        };
    }

    let corpora = match upload_corpora(state, &form.corpus) {
        Ok(corpora) => corpora,
        Err(error) => {
            return UploadResponse {
                ok: false,
                sha256: None,
                error: Some(format!("{} Request ID: {}", error, request_id)),
                stored: None,
            };
        }
    };
    let tags = match upload_tags(&form.tags) {
        Ok(tags) => tags,
        Err(error) => {
            return UploadResponse {
                ok: false,
                sha256: None,
                error: Some(format!("{} Request ID: {}", error, request_id)),
                stored: None,
            };
        }
    };
    info!(
        "upload start request_id={} filename={:?} bytes={} corpora={:?} tags={:?} configured_index_collections={:?} format_override={:?} architecture={:?}",
        request_id,
        form.filename,
        form.bytes.len(),
        corpora,
        tags,
        default_collections(&state.ui.index.local),
        form.format,
        form.architecture
    );

    let magic_override = parse_magic_override(form.format.as_deref());
    let architecture_override = if matches!(magic_override, Some(Magic::CODE)) {
        parse_architecture_override(form.architecture.as_deref())
    } else {
        None
    };
    let detected_magic = Magic::from_bytes(&form.bytes);
    if matches!(magic_override, Some(Magic::CODE))
        && matches!(detected_magic, Magic::PE | Magic::ELF | Magic::MACHO)
    {
        return UploadResponse {
            ok: false,
            sha256: None,
            error: Some(format!(
                "shellcode format cannot be used for detected {} input. Request ID: {}",
                detected_magic, request_id
            )),
            stored: None,
        };
    }
    if matches!(magic_override, Some(Magic::CODE)) && architecture_override.is_none() {
        return UploadResponse {
            ok: false,
            sha256: None,
            error: Some(format!(
                "shellcode uploads require an architecture value. Request ID: {}",
                request_id
            )),
            stored: None,
        };
    }

    let sha256 = match state.index.sample_put(&form.bytes) {
        Ok(sha256) => {
            info!(
                "upload sample stored request_id={} sha256={}",
                request_id, sha256
            );
            sha256
        }
        Err(error) => {
            warn!(
                "upload sample store failed request_id={} error={}",
                request_id, error
            );
            return UploadResponse {
                ok: false,
                sha256: None,
                error: Some(format!(
                    "failed to store sample: {} Request ID: {}",
                    error, request_id
                )),
                stored: None,
            };
        }
    };

    info!(
        "upload accepted request_id={} sha256={} corpora={:?} tags={:?} indexing_authority=binlex-server",
        request_id, sha256, corpora, tags
    );

    if let Err(error) = write_sample_status(
        state.database.as_ref(),
        &sha256,
        SampleStatus::Pending,
        None,
        Some(request_id),
    ) {
        warn!(
            "upload status queue failed request_id={} sha256={} error={}",
            request_id, sha256, error
        );
        return UploadResponse {
            ok: false,
            sha256: Some(sha256),
            error: Some(format!(
                "failed to queue upload analysis status: {} Request ID: {}",
                error, request_id
            )),
            stored: None,
        };
    }

    let client = state.client.clone();
    let database = state.database.clone();
    let index = state.index.clone();
    let bytes = form.bytes;
    let corpora_for_background = corpora.clone();
    let tags_for_background = tags.clone();
    let sha256_for_background = sha256.clone();
    let request_id_for_background = request_id.to_string();
    let username_for_background = username.to_string();
    let selector = configured_selector(state);
    let collections = default_collections(&state.ui.index.local);
    let analysis_config = state.analysis_config.clone();
    let spawn_result = thread::Builder::new()
        .name("binlex-web-upload-analyze".to_string())
        .spawn(move || {
            let upload_started_at = std::time::Instant::now();
            if let Err(error) = write_sample_status(
                database.as_ref(),
                &sha256_for_background,
                SampleStatus::Processing,
                None,
                Some(&request_id_for_background),
            ) {
                warn!(
                    "upload status processing failed request_id={} sha256={} error={}",
                    request_id_for_background, sha256_for_background, error
                );
            }
            info!(
                "upload analysis pending request_id={} sha256={} corpora={:?} tags={:?} indexing_authority=binlex-server",
                request_id_for_background, sha256_for_background, corpora_for_background, tags_for_background
            );
            let analyze_started_at = std::time::Instant::now();
            match client.analyze_bytes_response_with_corpora_collections_and_request_id(
                &bytes,
                magic_override,
                architecture_override,
                &corpora_for_background,
                &collections,
                Some(&request_id_for_background),
            ) {
                Ok(response) => {
                    let response_selector = response.selector.clone();
                    let selected_vectors = response.selected;
                    let snapshot = response.snapshot;
                    let configured_selector = selector.clone();
                    let selector = response_selector
                        .clone()
                        .unwrap_or_else(|| configured_selector.clone());
                    if response_selector.as_deref() != Some(configured_selector.as_str()) {
                        warn!(
                            "upload selector mismatch request_id={} sha256={} configured_selector={} response_selector={:?}",
                            request_id_for_background,
                            sha256_for_background,
                            configured_selector,
                            response_selector
                        );
                    }
                    let graph = match Graph::from_snapshot(snapshot, analysis_config.clone()) {
                        Ok(graph) => graph,
                        Err(error) => {
                            let error_message =
                                format!("failed to reconstruct analyzed graph: {}", error);
                            let _ = write_sample_status(
                                database.as_ref(),
                                &sha256_for_background,
                                SampleStatus::Failed,
                                Some(error_message.clone()),
                                Some(&request_id_for_background),
                            );
                            warn!(
                                "upload graph reconstruction failed request_id={} sha256={} error={}",
                                request_id_for_background, sha256_for_background, error
                            );
                            return;
                        }
                    };
                    let analyze_elapsed = analyze_started_at.elapsed();
                    let function_count = graph.functions().len();
                    let block_count = graph.blocks().len();
                    let instruction_count = graph.instructions().len();
                    let indexed_entity_count = collections
                        .iter()
                        .map(|collection| match collection {
                            Collection::Function => function_count,
                            Collection::Block => block_count,
                            Collection::Instruction => instruction_count,
                        })
                        .sum::<usize>();
                    info!(
                        "upload analysis complete request_id={} sha256={} architecture={} functions={} blocks={} instructions={} elapsed_ms={}",
                        request_id_for_background,
                        sha256_for_background,
                        graph.architecture,
                        function_count,
                        block_count,
                        instruction_count,
                        analyze_elapsed.as_millis()
                    );
                    let index_started_at = std::time::Instant::now();
                    info!(
                        "upload indexing start request_id={} sha256={} username={} corpora={:?} tags={:?} collections={:?} selector={} indexed_entities={}",
                        request_id_for_background,
                        sha256_for_background,
                        username_for_background,
                        corpora_for_background,
                        tags_for_background,
                        collections,
                        selector,
                        indexed_entity_count
                    );
                    if let Err(error) = index.graph_many_as(
                        &corpora_for_background,
                        &sha256_for_background,
                        &graph,
                        &[],
                        None,
                        None,
                        &username_for_background,
                    ) {
                        let error_message =
                            format!("failed to persist analyzed graph snapshot: {}", error);
                        if let Err(status_error) = write_sample_status(
                            database.as_ref(),
                            &sha256_for_background,
                            SampleStatus::Failed,
                            Some(error_message.clone()),
                            Some(&request_id_for_background),
                        ) {
                            warn!(
                                "upload status failed write failed request_id={} sha256={} error={}",
                                request_id_for_background, sha256_for_background, status_error
                            );
                        }
                        warn!(
                            "upload graph snapshot staging failed request_id={} sha256={} error={}",
                            request_id_for_background, sha256_for_background, error
                        );
                        return;
                    }
                    let indexed_entity_count = match index_selected_vectors(
                        &index,
                        &graph,
                        &selected_vectors,
                        &corpora_for_background,
                        &sha256_for_background,
                        &collections,
                        &username_for_background,
                    ) {
                        Ok(indexed) => indexed,
                        Err(error) => {
                            let error_message = format!("failed to index analyzed graph: {}", error);
                            if let Err(status_error) = write_sample_status(
                                database.as_ref(),
                                &sha256_for_background,
                                SampleStatus::Failed,
                                Some(error_message.clone()),
                                Some(&request_id_for_background),
                            ) {
                                warn!(
                                    "upload status failed write failed request_id={} sha256={} error={}",
                                    request_id_for_background, sha256_for_background, status_error
                                );
                            }
                            warn!(
                                "upload indexing failed request_id={} sha256={} error={}",
                                request_id_for_background, sha256_for_background, error
                            );
                            return;
                        }
                    };
                    if indexed_entity_count == 0 {
                        let error_message = format!(
                            "selector {} returned no vectors for collections {:?}",
                            selector, collections
                        );
                        if let Err(status_error) = write_sample_status(
                            database.as_ref(),
                            &sha256_for_background,
                            SampleStatus::Failed,
                            Some(error_message.clone()),
                            Some(&request_id_for_background),
                        ) {
                            warn!(
                                "upload status failed write failed request_id={} sha256={} error={}",
                                request_id_for_background, sha256_for_background, status_error
                            );
                        }
                        warn!(
                            "upload indexing failed request_id={} sha256={} error={}",
                            request_id_for_background, sha256_for_background, error_message
                        );
                        return;
                    }
                    info!(
                        "upload indexing staging complete request_id={} sha256={} indexed_entities={} staging_elapsed_ms={}",
                        request_id_for_background,
                        sha256_for_background,
                        indexed_entity_count,
                        index_started_at.elapsed().as_millis()
                    );
                    let commit_started_at = std::time::Instant::now();
                    info!(
                        "upload indexing commit start request_id={} sha256={} indexed_entities={}",
                        request_id_for_background,
                        sha256_for_background,
                        indexed_entity_count
                    );
                    if let Err(error) = index.commit() {
                        let error_message = format!("failed to commit indexed graph: {}", error);
                        if let Err(status_error) = write_sample_status(
                            database.as_ref(),
                            &sha256_for_background,
                            SampleStatus::Failed,
                            Some(error_message.clone()),
                            Some(&request_id_for_background),
                        ) {
                            warn!(
                                "upload status failed write failed request_id={} sha256={} error={}",
                                request_id_for_background, sha256_for_background, status_error
                            );
                        }
                        warn!(
                            "upload index commit failed request_id={} sha256={} error={}",
                            request_id_for_background, sha256_for_background, error
                        );
                        return;
                    }
                    if !tags_for_background.is_empty() {
                        let timestamp = Utc::now().to_rfc3339();
                        let mut tag_records = Vec::new();
                        for collection in &collections {
                            match collection {
                                Collection::Function => {
                                    for function in graph.functions() {
                                        for tag in &tags_for_background {
                                            tag_records.push(binlex::databases::CollectionTagRecord {
                                                sha256: sha256_for_background.clone(),
                                                collection: Collection::Function,
                                                address: function.address(),
                                                tag: tag.clone(),
                                                username: username_for_background.clone(),
                                                timestamp: timestamp.clone(),
                                            });
                                        }
                                    }
                                }
                                Collection::Block => {
                                    for block in graph.blocks() {
                                        for tag in &tags_for_background {
                                            tag_records.push(binlex::databases::CollectionTagRecord {
                                                sha256: sha256_for_background.clone(),
                                                collection: Collection::Block,
                                                address: block.address(),
                                                tag: tag.clone(),
                                                username: username_for_background.clone(),
                                                timestamp: timestamp.clone(),
                                            });
                                        }
                                    }
                                }
                                Collection::Instruction => {
                                    for instruction in graph.instructions() {
                                        for tag in &tags_for_background {
                                            tag_records.push(binlex::databases::CollectionTagRecord {
                                                sha256: sha256_for_background.clone(),
                                                collection: Collection::Instruction,
                                                address: instruction.address,
                                                tag: tag.clone(),
                                                username: username_for_background.clone(),
                                                timestamp: timestamp.clone(),
                                            });
                                        }
                                    }
                                }
                            }
                        }
                        if let Err(error) = database.as_ref().collection_tag_add_many(&tag_records)
                        {
                            let error_message =
                                format!("failed to apply upload tags after indexing: {}", error);
                            let _ = write_sample_status(
                                database.as_ref(),
                                &sha256_for_background,
                                SampleStatus::Failed,
                                Some(error_message.clone()),
                                Some(&request_id_for_background),
                            );
                            warn!(
                                "upload tag application failed request_id={} sha256={} error={}",
                                request_id_for_background,
                                sha256_for_background,
                                error
                            );
                            return;
                        }
                    }
                    let commit_elapsed = commit_started_at.elapsed();
                    let total_elapsed = upload_started_at.elapsed();
                    let indexing_elapsed = index_started_at.elapsed();
                    info!(
                        "upload indexing complete request_id={} sha256={} indexed_entities={} indexing_elapsed_ms={} commit_elapsed_ms={} total_elapsed_ms={}",
                        request_id_for_background,
                        sha256_for_background,
                        indexed_entity_count,
                        indexing_elapsed.as_millis(),
                        commit_elapsed.as_millis(),
                        total_elapsed.as_millis()
                    );
                    if let Err(error) = write_sample_status(
                        database.as_ref(),
                        &sha256_for_background,
                        SampleStatus::Complete,
                        None,
                        Some(&request_id_for_background),
                    ) {
                        warn!(
                            "upload status complete failed request_id={} sha256={} error={}",
                            request_id_for_background, sha256_for_background, error
                        );
                    }
                    info!(
                        "upload finalize complete request_id={} sha256={} architecture={} functions={} blocks={} instructions={} username={} corpora={:?} tags={:?} collections={:?} total_elapsed_ms={}",
                        request_id_for_background,
                        sha256_for_background,
                        graph.architecture,
                        function_count,
                        block_count,
                        instruction_count,
                        username_for_background,
                        corpora_for_background,
                        tags_for_background,
                        collections,
                        total_elapsed.as_millis()
                    );
                }
                Err(error) => {
                    if let Err(status_error) = write_sample_status(
                        database.as_ref(),
                        &sha256_for_background,
                        SampleStatus::Failed,
                        Some(error.to_string()),
                        Some(&request_id_for_background),
                    ) {
                        warn!(
                            "upload status failed write failed request_id={} sha256={} error={}",
                            request_id_for_background, sha256_for_background, status_error
                        );
                    }
                    warn!(
                        "upload analysis failed request_id={} sha256={} error={}",
                        request_id_for_background, sha256_for_background, error
                    );
                }
            }
        })
        .map_err(|error| UploadResponse {
            ok: false,
            sha256: Some(sha256.clone()),
            error: Some(format!(
                "failed to queue upload analysis: {} Request ID: {}",
                error, request_id
            )),
            stored: None,
        });

    if let Err(response) = spawn_result {
        if let Some(sha256) = response.sha256.as_deref() {
            let _ = write_sample_status(
                state.database.as_ref(),
                sha256,
                SampleStatus::Failed,
                response.error.clone(),
                Some(request_id),
            );
        }
        return response;
    }

    UploadResponse {
        ok: true,
        sha256: Some(sha256),
        error: None,
        stored: None,
    }
}

fn write_sample_status(
    database: &LocalDB,
    sha256: &str,
    status: SampleStatus,
    error_message: Option<String>,
    id: Option<&str>,
) -> Result<(), binlex::databases::localdb::Error> {
    database.sample_status_set(&SampleStatusRecord {
        sha256: sha256.to_string(),
        status,
        timestamp: Utc::now().to_rfc3339(),
        error_message,
        id: id.map(ToString::to_string),
    })
}

impl UploadStatusResponse {
    fn from_status(status: SampleStatus) -> &'static str {
        match status {
            SampleStatus::Pending => "pending",
            SampleStatus::Processing => "processing",
            SampleStatus::Complete => "complete",
            SampleStatus::Failed => "failed",
            SampleStatus::Canceled => "canceled",
            SampleStatus::Stored => "stored",
        }
    }
}

impl From<SampleStatusRecord> for UploadStatusResponse {
    fn from(value: SampleStatusRecord) -> Self {
        Self {
            sha256: value.sha256,
            status: Self::from_status(value.status).to_string(),
            timestamp: value.timestamp,
            error_message: value.error_message,
            id: value.id,
        }
    }
}

fn upload_corpora(state: &AppState, values: &[String]) -> Result<Vec<String>, String> {
    let mut corpora = values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(|value| {
            if value.chars().any(char::is_whitespace) {
                Err(format!("corpus '{}' must not contain whitespace", value))
            } else {
                Ok(value.to_string())
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    corpora.sort();
    corpora.dedup();
    let default_corpus = state.ui.index.local.default_corpus.clone();
    if corpora.is_empty() {
        corpora.push(default_corpus.clone());
    } else if !corpora
        .iter()
        .any(|value| value.eq_ignore_ascii_case(&default_corpus))
    {
        corpora.push(default_corpus);
        corpora.sort();
        corpora.dedup();
    }
    Ok(corpora)
}

fn upload_corpus_options(state: &AppState, existing: &[String]) -> Vec<String> {
    let mut corpora = state.ui.index.local.default_corpora.clone();
    corpora.extend(existing.iter().cloned());
    if !corpora
        .iter()
        .any(|value| value.eq_ignore_ascii_case(&state.ui.index.local.default_corpus))
    {
        corpora.push(state.ui.index.local.default_corpus.clone());
    }
    corpora.retain(|value| !value.trim().is_empty());
    corpora.sort();
    corpora.dedup();
    corpora
}

fn upload_tags(values: &[String]) -> Result<Vec<String>, String> {
    let mut tags = values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(|value| {
            if value.chars().any(char::is_whitespace) {
                Err(format!("tag '{}' must not contain whitespace", value))
            } else {
                Ok(value.to_string())
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    tags.sort();
    tags.dedup_by(|lhs, rhs| lhs.eq_ignore_ascii_case(rhs));
    Ok(tags)
}

fn upload_default_selected_corpora(state: &AppState, options: &[String]) -> Vec<String> {
    if options
        .iter()
        .any(|value| value == &state.ui.index.local.default_corpus)
    {
        return vec![state.ui.index.local.default_corpus.clone()];
    }
    options
        .first()
        .cloned()
        .map(|value| vec![value])
        .unwrap_or_default()
}
