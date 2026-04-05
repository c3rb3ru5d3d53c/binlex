#[derive(OpenApi)]
#[openapi(
    paths(
        stage_index_graph,
        stage_index_function,
        stage_index_block,
        stage_index_instruction,
        commit_index,
        clear_index,
        get_collection_corpora_api,
        add_collection_corpus_api,
        remove_collection_corpus_api,
        get_sample_tags,
        add_sample_tag,
        remove_sample_tag,
        replace_sample_tags,
        search_tags_api,
        add_tag_api,
        get_collection_tags,
        add_collection_tag_api,
        remove_collection_tag_api,
        replace_collection_tags_api,
        search_sample_tags_api,
        search_collection_tags_api,
        version_api,
        create_token_api,
        clear_token_api,
        auth_role_create_api,
        auth_role_get_api,
        auth_roles_search_api,
        auth_role_delete_api,
        auth_user_create_api,
        auth_user_get_api,
        auth_users_search_api,
        auth_user_disable_api,
        auth_user_enable_api,
        auth_user_reset_api,
        search_api,
        search_detail_api,
        add_corpus_api,
        search_corpora_api,
        upload,
        upload_status,
        download_sample,
        download_samples,
        download_json
    ),
    components(schemas(
        CorporaApiParams,
        CorpusActionRequest,
        SearchResponse,
        SearchDetailParams,
        SearchRequest,
        SearchRowDetailResponse,
        IndexCommitRequest,
        IndexActionResponse,
        IndexGraphRequest,
        IndexFunctionRequest,
        IndexBlockRequest,
        IndexInstructionRequest,
        SampleTagsParams,
        CollectionTagsParams,
        CollectionCorporaParams,
        SearchTagsParams,
        SearchAssignedTagsParams,
        SearchCollectionTagsParams,
        TagActionRequest,
        SampleTagActionRequest,
        SampleTagsReplaceRequest,
        CollectionTagActionRequest,
        CollectionCorpusActionRequest,
        CollectionTagsReplaceRequest,
        CorporaResponse,
        TagsResponse,
        TagsCatalogResponse,
        TagsActionResponse,
        TagSearchItemResponse,
        TagSearchResponse,
        CollectionTagSearchItemResponse,
        CollectionTagSearchResponse,
        VersionResponse,
        TokenCreateRequest,
        TokenCreateResponse,
        TokenClearRequest,
        TokenActionResponse,
        AuthRoleCreateRequest,
        AuthRoleGetParams,
        AuthSearchParams,
        AuthRoleResponse,
        AuthRoleSearchResponse,
        AuthRoleDeleteRequest,
        AuthUserCreateRequest,
        AuthUserNameRequest,
        AuthUserGetParams,
        AuthUserResponse,
        AuthUserCreateResponse,
        AuthUserResetResponse,
        AuthUserSearchResponse,
        UploadResponse,
        UploadStatusParams,
        UploadStatusResponse,
        UploadSampleRequestDoc,
        DownloadSampleParams,
        DownloadSamplesParams,
        DownloadJsonParams,
        ApiErrorResponse
    )),
    modifiers(&ApiDocSecurity),
    tags(
        (name = "System", description = "Service health and version information."),
        (name = "Search", description = "Search endpoints and corpus lookup."),
        (name = "Index", description = "Graph and entity indexing operations."),
        (name = "Upload", description = "Sample upload and upload status endpoints."),
        (name = "Download", description = "Sample and JSON download endpoints."),
        (name = "Tags", description = "Sample and collection tag operations."),
        (name = "Tokens", description = "Temporary token lifecycle endpoints."),
        (name = "Auth", description = "Role and user management endpoints.")
    ),
    info(
        title = "Binlex Web API",
        version = "v1",
        description = "Versioned public API for binlex-web. The browser UI routes are intentionally excluded. Protected endpoints may use `Authorization: Bearer <api_key>` and/or `Token: <temporary_token>` depending on binlex-web configuration."
    )
)]
struct ApiDoc;

struct ApiDocSecurity;

impl Modify for ApiDocSecurity {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        openapi.info = InfoBuilder::from(openapi.info.clone())
            .description(Some("Versioned public API for binlex-web. The browser UI routes are intentionally excluded. Protected endpoints may use `Authorization: Bearer <api_key>` and/or `Token: <temporary_token>` depending on binlex-web configuration.".to_string()))
            .build();

        let bearer = SecurityScheme::Http(
            HttpBuilder::new()
                .scheme(HttpAuthScheme::Bearer)
                .bearer_format("API Key")
                .description(Some(
                    "Use `Authorization: Bearer <api_key>` for protected endpoints.".to_string(),
                ))
                .build(),
        );
        let token = SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("Token")));

        openapi.components = Some(
            openapi
                .components
                .clone()
                .map(ComponentsBuilder::from)
                .unwrap_or_else(ComponentsBuilder::new)
                .security_scheme("bearer_auth", bearer)
                .security_scheme("token_header", token)
                .build(),
        );
    }
}

fn deserialize_string_or_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrVec {
        One(String),
        Many(Vec<String>),
    }

    Ok(match Option::<StringOrVec>::deserialize(deserializer)? {
        Some(StringOrVec::One(value)) => value
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect(),
        Some(StringOrVec::Many(values)) => values,
        None => Vec::new(),
    })
}

#[derive(Debug)]
struct AppError {
    message: String,
    status: StatusCode,
    request_id: Option<String>,
}

impl AppError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            status: StatusCode::INTERNAL_SERVER_ERROR,
            request_id: None,
        }
    }

    fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            status: StatusCode::UNAUTHORIZED,
            request_id: None,
        }
    }

    fn forbidden(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            status: StatusCode::FORBIDDEN,
            request_id: None,
        }
    }

    fn with_request_id(message: impl Into<String>, request_id: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            status: StatusCode::INTERNAL_SERVER_ERROR,
            request_id: Some(request_id.into()),
        }
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for AppError {}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let body = Json(ApiErrorResponse {
            error: self.message,
            request_id: self.request_id,
        });
        (self.status, body).into_response()
    }
}
