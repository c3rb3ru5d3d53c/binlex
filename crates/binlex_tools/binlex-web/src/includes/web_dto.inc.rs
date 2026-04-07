#[derive(Clone, Default, Deserialize, Serialize, ToSchema)]
struct PageParams {
    #[serde(default)]
    search: Option<String>,
    #[serde(default)]
    query: String,
    #[serde(default)]
    uploaded_sha256: Option<String>,
    #[serde(default, deserialize_with = "deserialize_string_or_vec")]
    corpora: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_string_or_vec")]
    architectures: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_string_or_vec")]
    collections: Vec<String>,
    #[serde(default)]
    top_k: Option<usize>,
    #[serde(default)]
    page: Option<usize>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    warning: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Clone, Default, Deserialize, Serialize, ToSchema)]
struct SearchRequest {
    #[serde(default)]
    query: String,
    #[serde(default)]
    top_k: Option<usize>,
    #[serde(default)]
    page: Option<usize>,
}

#[derive(Deserialize, ToSchema)]
struct IndexCommitRequest {}

#[derive(Serialize, ToSchema)]
struct IndexActionResponse {
    ok: bool,
}

#[derive(Deserialize, ToSchema)]
struct IndexGraphRequest {
    #[schema(example = "d60f9eaa4f62f0ee84531d9aa633c5bb390ea0056953e58d80b9a62277dbe5c5")]
    sha256: String,
    #[schema(value_type = Object)]
    graph: Value,
    #[serde(default)]
    #[schema(value_type = Object, nullable = true)]
    attributes: Option<Value>,
    #[serde(default, deserialize_with = "deserialize_string_or_vec")]
    collections: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_string_or_vec")]
    corpora: Vec<String>,
}

#[derive(Deserialize, ToSchema)]
struct IndexFunctionRequest {
    #[schema(example = "d60f9eaa4f62f0ee84531d9aa633c5bb390ea0056953e58d80b9a62277dbe5c5")]
    sha256: String,
    #[schema(value_type = Object)]
    function: Value,
    #[serde(default, deserialize_with = "deserialize_string_or_vec")]
    corpora: Vec<String>,
}

#[derive(Deserialize, ToSchema)]
struct IndexBlockRequest {
    #[schema(example = "d60f9eaa4f62f0ee84531d9aa633c5bb390ea0056953e58d80b9a62277dbe5c5")]
    sha256: String,
    #[schema(value_type = Object)]
    block: Value,
    #[serde(default, deserialize_with = "deserialize_string_or_vec")]
    corpora: Vec<String>,
}

#[derive(Deserialize, ToSchema)]
struct IndexInstructionRequest {
    #[schema(example = "d60f9eaa4f62f0ee84531d9aa633c5bb390ea0056953e58d80b9a62277dbe5c5")]
    sha256: String,
    #[schema(value_type = Object)]
    instruction: Value,
    #[serde(default, deserialize_with = "deserialize_string_or_vec")]
    corpora: Vec<String>,
}

#[derive(Default)]
struct UploadForm {
    filename: Option<String>,
    bytes: Vec<u8>,
    format: Option<String>,
    architecture: Option<String>,
    corpus: Vec<String>,
    tags: Vec<String>,
}

#[derive(Default)]
pub(crate) struct PageData {
    pub(crate) corpora_options: Vec<String>,
    pub(crate) architecture_options: Vec<String>,
    pub(crate) collection_options: Vec<String>,
    pub(crate) query_completion_specs: Vec<QueryCompletionSpec>,
    pub(crate) status: UiStatus,
    pub(crate) uploaded_sha256: Option<String>,
    pub(crate) message: Option<String>,
    pub(crate) warning: Option<String>,
    pub(crate) error: Option<String>,
    pub(crate) query: String,
    pub(crate) top_k: usize,
    pub(crate) page: usize,
    pub(crate) total_results: usize,
    pub(crate) has_previous_page: bool,
    pub(crate) has_next_page: bool,
    pub(crate) rows: Vec<ResultRow>,
    pub(crate) upload_format_options: Vec<String>,
    pub(crate) upload_architecture_options: Vec<String>,
    pub(crate) upload_corpus_options: Vec<String>,
    pub(crate) upload_corpora_locked: bool,
    pub(crate) upload_selected_corpora: Vec<String>,
    pub(crate) upload_tag_options: Vec<String>,
    pub(crate) upload_selected_tags: Vec<String>,
    pub(crate) uploads_enabled: bool,
    pub(crate) upload_button_enabled: bool,
    pub(crate) sample_downloads_enabled: bool,
    pub(crate) auth_bootstrap_required: bool,
    pub(crate) auth_registration_enabled: bool,
    pub(crate) auth_two_factor_required: bool,
    pub(crate) auth_user: Option<AuthUserProfile>,
}

#[derive(Default)]
pub(crate) struct UiStatus {
    pub(crate) server_ok: bool,
    pub(crate) index_ok: bool,
    pub(crate) database_ok: bool,
}

#[derive(Clone, Default, Serialize)]
pub(crate) struct AuthUserProfile {
    pub(crate) username: String,
    pub(crate) key: String,
    pub(crate) role: String,
    pub(crate) profile_picture: Option<String>,
    pub(crate) two_factor_enabled: bool,
    pub(crate) two_factor_required: bool,
}

#[derive(Deserialize, IntoParams, ToSchema)]
struct CorporaApiParams {
    #[serde(default)]
    #[schema(example = "good")]
    q: String,
}

#[derive(Deserialize, Serialize, ToSchema)]
struct CorpusActionRequest {
    #[schema(example = "goodware")]
    corpus: String,
}

#[derive(Serialize, ToSchema)]
struct UploadResponse {
    #[schema(example = true)]
    ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = "d60f9eaa4f62f0ee84531d9aa633c5bb390ea0056953e58d80b9a62277dbe5c5")]
    sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = "upload exceeds max size of 209715200 bytes")]
    error: Option<String>,
}

#[derive(Deserialize, IntoParams, ToSchema)]
struct UploadStatusParams {
    #[schema(example = "d60f9eaa4f62f0ee84531d9aa633c5bb390ea0056953e58d80b9a62277dbe5c5")]
    sha256: String,
}

#[derive(Serialize, ToSchema)]
struct UploadStatusResponse {
    #[schema(example = "d60f9eaa4f62f0ee84531d9aa633c5bb390ea0056953e58d80b9a62277dbe5c5")]
    sha256: String,
    #[schema(example = "processing")]
    status: String,
    #[schema(example = "2026-04-01T12:00:00Z")]
    timestamp: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = "analysis failed", nullable = true)]
    error_message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = "req_123", nullable = true)]
    id: Option<String>,
}

#[derive(Serialize, ToSchema)]
struct SearchResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    warning: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    query: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    uploaded_sha256: Option<String>,
    page: usize,
    top_k: usize,
    total_results: usize,
    has_previous_page: bool,
    has_next_page: bool,
    sample_downloads_enabled: bool,
    results: Vec<SearchRowResponse>,
}

#[derive(Deserialize, Serialize, ToSchema)]
struct ActionYaraRequest {
    #[serde(default)]
    query: String,
    #[serde(default)]
    items: Vec<ActionYaraItemRequest>,
}

#[derive(Deserialize, Serialize, ToSchema)]
struct ActionYaraItemRequest {
    #[schema(example = "default")]
    corpus: String,
    #[schema(example = "d60f9eaa4f62f0ee84531d9aa633c5bb390ea0056953e58d80b9a62277dbe5c5")]
    sha256: String,
    #[schema(example = "function")]
    collection: String,
    #[schema(example = "amd64")]
    architecture: String,
    #[schema(example = 4198400)]
    address: u64,
}

#[derive(Deserialize, IntoParams, ToSchema)]
struct SearchDetailParams {
    #[schema(example = "d60f9eaa4f62f0ee84531d9aa633c5bb390ea0056953e58d80b9a62277dbe5c5")]
    sha256: String,
    #[schema(example = "function")]
    collection: String,
    #[schema(example = "amd64")]
    architecture: String,
    #[schema(example = 4198400)]
    address: u64,
    #[serde(default)]
    #[schema(nullable = true, example = "CreateFileW")]
    symbol: Option<String>,
}

#[derive(Serialize, ToSchema)]
struct SearchRowResponse {
    side: String,
    grouped: bool,
    group_end: bool,
    detail_loaded: bool,
    object_id: String,
    timestamp: String,
    username: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    profile_picture: Option<String>,
    size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    score: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    similarity_score: Option<f32>,
    vector: Vec<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Object, nullable = true)]
    json: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    symbol: Option<String>,
    architecture: String,
    sha256: String,
    collection: String,
    address: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cyclomatic_complexity: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    average_instructions_per_block: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    number_of_instructions: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    number_of_blocks: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    markov: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    entropy: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    contiguous: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    chromosome_entropy: Option<f64>,
    embedding: String,
    embeddings: u64,
    corpora: Vec<String>,
    #[serde(default)]
    collection_tag_count: usize,
    #[serde(default)]
    collection_comment_count: usize,
}

#[derive(Serialize, ToSchema)]
struct SearchRowDetailResponse {
    detail_loaded: bool,
    object_id: String,
    timestamp: String,
    username: String,
    size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    score: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    similarity_score: Option<f32>,
    vector: Vec<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Object, nullable = true)]
    json: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    symbol: Option<String>,
    architecture: String,
    sha256: String,
    collection: String,
    address: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cyclomatic_complexity: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    average_instructions_per_block: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    number_of_instructions: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    number_of_blocks: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    markov: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    entropy: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    contiguous: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    chromosome_entropy: Option<f64>,
    embedding: String,
    embeddings: u64,
    corpora: Vec<String>,
}

#[derive(Deserialize, Serialize, IntoParams, ToSchema)]
struct CollectionCommentsParams {
    #[schema(example = "d60f9eaa4f62f0ee84531d9aa633c5bb390ea0056953e58d80b9a62277dbe5c5")]
    sha256: String,
    #[schema(example = "function")]
    collection: String,
    #[schema(example = 4198400)]
    address: u64,
    #[serde(default)]
    page: Option<usize>,
    #[serde(default)]
    page_size: Option<usize>,
}

#[derive(Deserialize, Serialize, ToSchema)]
struct EntityCommentCreateRequest {
    #[schema(example = "d60f9eaa4f62f0ee84531d9aa633c5bb390ea0056953e58d80b9a62277dbe5c5")]
    sha256: String,
    #[schema(example = "function")]
    collection: String,
    #[schema(example = 4198400)]
    address: u64,
    #[schema(example = "Resolves imports lazily and caches the resulting function pointers.")]
    body: String,
}

#[derive(Serialize, ToSchema)]
struct EntityCommentResponse {
    id: i64,
    sha256: String,
    collection: String,
    address: u64,
    actor: MetadataActorResponse,
    timestamp: String,
    body: String,
}

#[derive(Serialize, ToSchema)]
struct EntityCommentsResponse {
    sha256: String,
    collection: String,
    address: u64,
    items: Vec<EntityCommentResponse>,
    page: usize,
    page_size: usize,
    total_results: usize,
    has_next: bool,
}

#[derive(Deserialize, Serialize, IntoParams, ToSchema)]
struct AdminCommentsSearchParams {
    #[serde(default)]
    #[schema(example = "dispatcher")]
    q: String,
    #[serde(default)]
    page: Option<usize>,
    #[serde(default)]
    page_size: Option<usize>,
}

#[derive(Serialize, ToSchema)]
struct AdminCommentsSearchResponse {
    items: Vec<EntityCommentResponse>,
    page: usize,
    page_size: usize,
    total_results: usize,
    has_next: bool,
}

#[derive(Serialize, ToSchema)]
struct CommentActionResponse {
    ok: bool,
}

#[derive(Deserialize, Serialize, IntoParams, ToSchema)]
struct SampleTagsParams {
    #[schema(example = "d60f9eaa4f62f0ee84531d9aa633c5bb390ea0056953e58d80b9a62277dbe5c5")]
    sha256: String,
}

#[derive(Deserialize, Serialize, IntoParams, ToSchema)]
struct CollectionTagsParams {
    #[schema(example = "d60f9eaa4f62f0ee84531d9aa633c5bb390ea0056953e58d80b9a62277dbe5c5")]
    sha256: String,
    #[schema(example = "function")]
    collection: String,
    #[schema(example = 4198400)]
    address: u64,
}

#[derive(Deserialize, Serialize, IntoParams, ToSchema)]
struct CollectionSymbolsParams {
    #[schema(example = "d60f9eaa4f62f0ee84531d9aa633c5bb390ea0056953e58d80b9a62277dbe5c5")]
    sha256: String,
    #[schema(example = "function")]
    collection: String,
    #[schema(example = "amd64")]
    architecture: String,
    #[schema(example = 4198400)]
    address: u64,
}

#[derive(Deserialize, Serialize, IntoParams, ToSchema)]
struct CollectionCorporaParams {
    #[schema(example = "d60f9eaa4f62f0ee84531d9aa633c5bb390ea0056953e58d80b9a62277dbe5c5")]
    sha256: String,
    #[schema(example = "function")]
    collection: String,
    #[schema(example = "amd64")]
    architecture: String,
    #[schema(example = 4198400)]
    address: u64,
}

#[derive(Deserialize, Serialize, IntoParams, ToSchema)]
struct SearchSymbolsParams {
    #[serde(default)]
    #[schema(example = "Create")]
    q: String,
    #[serde(default)]
    #[schema(example = 64)]
    limit: Option<usize>,
}

#[derive(Deserialize, Serialize, IntoParams, ToSchema)]
struct SearchTagsParams {
    #[serde(default)]
    #[schema(example = "shared")]
    q: String,
    #[serde(default)]
    #[schema(example = 64)]
    limit: Option<usize>,
}

#[derive(Deserialize, Serialize, IntoParams, ToSchema)]
struct SearchAssignedTagsParams {
    #[serde(default)]
    #[schema(example = "shared")]
    q: String,
    #[serde(default)]
    page: Option<usize>,
    #[serde(default)]
    page_size: Option<usize>,
}

#[derive(Deserialize, Serialize, IntoParams, ToSchema)]
struct SearchCollectionTagsParams {
    #[serde(default)]
    #[schema(example = "shared")]
    q: String,
    #[serde(default)]
    #[schema(example = "function", nullable = true)]
    collection: Option<String>,
    #[serde(default)]
    page: Option<usize>,
    #[serde(default)]
    page_size: Option<usize>,
}

#[derive(Deserialize, Serialize, ToSchema)]
struct SampleTagActionRequest {
    #[schema(example = "d60f9eaa4f62f0ee84531d9aa633c5bb390ea0056953e58d80b9a62277dbe5c5")]
    sha256: String,
    #[schema(example = "fancybear")]
    tag: String,
}

#[derive(Deserialize, Serialize, ToSchema)]
struct SampleTagsReplaceRequest {
    #[schema(example = "d60f9eaa4f62f0ee84531d9aa633c5bb390ea0056953e58d80b9a62277dbe5c5")]
    sha256: String,
    tags: Vec<String>,
}

#[derive(Deserialize, Serialize, ToSchema)]
struct CollectionTagActionRequest {
    #[schema(example = "d60f9eaa4f62f0ee84531d9aa633c5bb390ea0056953e58d80b9a62277dbe5c5")]
    sha256: String,
    #[schema(example = "function")]
    collection: String,
    #[schema(example = 4198400)]
    address: u64,
    #[schema(example = "goodware")]
    tag: String,
}

#[derive(Deserialize, Serialize, ToSchema)]
struct CollectionTagsReplaceRequest {
    #[schema(example = "d60f9eaa4f62f0ee84531d9aa633c5bb390ea0056953e58d80b9a62277dbe5c5")]
    sha256: String,
    #[schema(example = "function")]
    collection: String,
    #[schema(example = 4198400)]
    address: u64,
    tags: Vec<String>,
}

#[derive(Deserialize, Serialize, ToSchema)]
struct CollectionSymbolActionRequest {
    #[schema(example = "d60f9eaa4f62f0ee84531d9aa633c5bb390ea0056953e58d80b9a62277dbe5c5")]
    sha256: String,
    #[schema(example = "function")]
    collection: String,
    #[schema(example = "amd64")]
    architecture: String,
    #[schema(example = 4198400)]
    address: u64,
    #[schema(example = "CreateFileW")]
    symbol: String,
}

#[derive(Deserialize, Serialize, ToSchema)]
struct CollectionSymbolsReplaceRequest {
    #[schema(example = "d60f9eaa4f62f0ee84531d9aa633c5bb390ea0056953e58d80b9a62277dbe5c5")]
    sha256: String,
    #[schema(example = "function")]
    collection: String,
    #[schema(example = "amd64")]
    architecture: String,
    #[schema(example = 4198400)]
    address: u64,
    symbols: Vec<String>,
}

#[derive(Deserialize, Serialize, ToSchema)]
struct SymbolActionRequest {
    #[schema(example = "CreateFileW")]
    symbol: String,
}

#[derive(Deserialize, Serialize, ToSchema)]
struct TagActionRequest {
    #[schema(example = "needs-review")]
    tag: String,
}

#[derive(Deserialize, Serialize, ToSchema)]
struct CollectionCorpusActionRequest {
    #[schema(example = "d60f9eaa4f62f0ee84531d9aa633c5bb390ea0056953e58d80b9a62277dbe5c5")]
    sha256: String,
    #[schema(example = "function")]
    collection: String,
    #[schema(example = "amd64")]
    architecture: String,
    #[schema(example = 4198400)]
    address: u64,
    #[schema(example = "goodware")]
    corpus: String,
}

#[derive(Serialize, ToSchema)]
struct MetadataActorResponse {
    username: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    profile_picture: Option<String>,
}

#[derive(Serialize, ToSchema)]
struct MetadataItemResponse {
    name: String,
    created_actor: MetadataActorResponse,
    created_timestamp: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    assigned_actor: Option<MetadataActorResponse>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    assigned_timestamp: Option<String>,
}

#[derive(Serialize, ToSchema)]
struct TagsResponse {
    #[schema(example = "d60f9eaa4f62f0ee84531d9aa633c5bb390ea0056953e58d80b9a62277dbe5c5")]
    sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    collection: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    address: Option<u64>,
    tags: Vec<MetadataItemResponse>,
}

#[derive(Serialize, ToSchema)]
struct SymbolsResponse {
    #[schema(example = "d60f9eaa4f62f0ee84531d9aa633c5bb390ea0056953e58d80b9a62277dbe5c5")]
    sha256: String,
    collection: String,
    architecture: String,
    address: u64,
    symbols: Vec<MetadataItemResponse>,
}

#[derive(Serialize, ToSchema)]
struct SymbolsCatalogResponse {
    symbols: Vec<MetadataItemResponse>,
    total_results: usize,
    has_next: bool,
}

#[derive(Serialize, ToSchema)]
struct TagsCatalogResponse {
    tags: Vec<MetadataItemResponse>,
    total_results: usize,
    has_next: bool,
}

#[derive(Serialize, ToSchema)]
struct CorporaResponse {
    #[schema(example = "d60f9eaa4f62f0ee84531d9aa633c5bb390ea0056953e58d80b9a62277dbe5c5")]
    sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    collection: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    architecture: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    address: Option<u64>,
    corpora: Vec<MetadataItemResponse>,
}

#[derive(Serialize, ToSchema)]
struct CorporaCatalogResponse {
    corpora: Vec<MetadataItemResponse>,
    total_results: usize,
}

#[derive(Serialize, ToSchema)]
struct TagsActionResponse {
    ok: bool,
}

#[derive(Serialize, ToSchema)]
struct TagSearchItemResponse {
    #[schema(example = "d60f9eaa4f62f0ee84531d9aa633c5bb390ea0056953e58d80b9a62277dbe5c5")]
    sha256: String,
    #[schema(example = "needs-review")]
    tag: String,
    #[schema(example = "2026-04-02T12:00:00Z")]
    timestamp: String,
}

#[derive(Serialize, ToSchema)]
struct TagSearchResponse {
    items: Vec<TagSearchItemResponse>,
    page: usize,
    page_size: usize,
    has_next: bool,
}

#[derive(Serialize, ToSchema)]
struct CollectionTagSearchItemResponse {
    #[schema(example = "d60f9eaa4f62f0ee84531d9aa633c5bb390ea0056953e58d80b9a62277dbe5c5")]
    sha256: String,
    #[schema(example = "function")]
    collection: String,
    #[schema(example = 4198400)]
    address: u64,
    #[schema(example = "goodware")]
    tag: String,
    #[schema(example = "2026-04-02T12:00:00Z")]
    timestamp: String,
}

#[derive(Serialize, ToSchema)]
struct CollectionTagSearchResponse {
    items: Vec<CollectionTagSearchItemResponse>,
    page: usize,
    page_size: usize,
    has_next: bool,
}

struct SearchPage {
    rows: Vec<ResultRow>,
    total_results: usize,
    has_next: bool,
    warning: Option<String>,
}

#[derive(Clone, Serialize)]
pub(crate) struct ResultRow {
    pub(crate) side: RowSide,
    pub(crate) result: SearchResult,
    pub(crate) score: Option<f32>,
    pub(crate) profile_picture: Option<String>,
    pub(crate) grouped: bool,
    pub(crate) group_end: bool,
    pub(crate) collection_tag_count: usize,
    pub(crate) collection_comment_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) enum RowSide {
    Lhs,
    Rhs,
}

impl RowSide {
    fn as_api_str(self) -> &'static str {
        match self {
            Self::Lhs => "lhs",
            Self::Rhs => "rhs",
        }
    }
}

#[derive(Clone)]
struct ComparePair {
    lhs: SearchResult,
    rhs: SearchResult,
    score: f32,
}

enum ExecutedStream {
    Search {
        results: Vec<SearchResult>,
        side: RowSide,
    },
    Compare {
        pairs: Vec<ComparePair>,
    },
}

#[derive(Deserialize, IntoParams, ToSchema)]
struct DownloadSampleParams {
    #[schema(example = "d60f9eaa4f62f0ee84531d9aa633c5bb390ea0056953e58d80b9a62277dbe5c5")]
    sha256: String,
}

#[derive(Deserialize, IntoParams, ToSchema)]
struct DownloadSamplesParams {
    #[serde(default, deserialize_with = "deserialize_string_or_vec")]
    #[schema(example = json!(["d60f9eaa4f62f0ee84531d9aa633c5bb390ea0056953e58d80b9a62277dbe5c5","116dfe7cc1c09cb0cf7b6d3936d6f2bbc0739a9267cf840fb873b142150253be"]))]
    sha256: Vec<String>,
}

#[derive(Deserialize, IntoParams, ToSchema)]
struct DownloadJsonParams {
    #[schema(example = "default")]
    corpus: String,
    #[schema(example = "d60f9eaa4f62f0ee84531d9aa633c5bb390ea0056953e58d80b9a62277dbe5c5")]
    sha256: String,
    #[schema(example = "function")]
    collection: String,
    #[schema(example = 4198400)]
    address: u64,
}

#[derive(Serialize, ToSchema)]
struct ApiErrorResponse {
    #[schema(example = "invalid sha256")]
    error: String,
    #[schema(
        example = "req_018f7e3d4a2b_00000001_5f0c2d71467c8a21",
        nullable = true
    )]
    request_id: Option<String>,
}

#[derive(Serialize, ToSchema)]
struct VersionResponse {
    #[schema(example = "2.0.0")]
    version: String,
}

#[derive(Deserialize, Serialize, ToSchema, Default)]
struct TokenCreateRequest {}

#[derive(Serialize, ToSchema)]
struct TokenCreateResponse {
    #[schema(example = "9f1a8c3d4e5f60718293a4b5c6d7e8f90123456789abcdef")]
    token: String,
    #[schema(example = "2026-04-03T18:00:00Z")]
    expires: String,
}

#[derive(Deserialize, Serialize, ToSchema)]
struct TokenClearRequest {
    #[schema(example = "9f1a8c3d4e5f60718293a4b5c6d7e8f90123456789abcdef")]
    token: String,
}

#[derive(Serialize, ToSchema)]
struct TokenActionResponse {
    ok: bool,
}

#[derive(Deserialize, Serialize, ToSchema)]
struct AuthBootstrapRequest {
    #[schema(example = "alice")]
    username: String,
    #[schema(example = "supersecret123")]
    password: String,
    #[schema(example = "supersecret123")]
    password_confirm: String,
}

#[derive(Deserialize, Serialize, ToSchema)]
struct AuthLoginRequest {
    #[schema(example = "alice")]
    username: String,
    #[schema(example = "supersecret123")]
    password: String,
}

#[derive(Deserialize, Serialize, ToSchema)]
struct AuthRegisterRequest {
    #[schema(example = "alice")]
    username: String,
    #[schema(example = "supersecret123")]
    password: String,
    #[schema(example = "supersecret123")]
    password_confirm: String,
    #[schema(example = "cap_123")]
    captcha_id: String,
    #[schema(example = "7f3ca9")]
    captcha_answer: String,
}

#[derive(Serialize, ToSchema)]
struct CaptchaResponse {
    captcha_id: String,
    image_base64: String,
    expires: String,
}

#[derive(Serialize, ToSchema)]
struct AuthUserResponse {
    username: String,
    key: String,
    role: String,
    enabled: bool,
    profile_picture: Option<String>,
    two_factor_enabled: bool,
    two_factor_required: bool,
    timestamp: String,
}

#[derive(Serialize, ToSchema)]
struct AuthSessionResponse {
    authenticated: bool,
    registration_enabled: bool,
    bootstrap_required: bool,
    #[serde(default)]
    two_factor_required: bool,
    #[serde(default)]
    two_factor_setup_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    challenge_token: Option<String>,
    user: Option<AuthUserResponse>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recovery_codes: Option<Vec<String>>,
}

#[derive(Serialize, ToSchema)]
struct TwoFactorSetupResponse {
    manual_secret: String,
    qr_svg: String,
}

#[derive(Deserialize, Serialize, ToSchema)]
struct TwoFactorSetupRequest {}

#[derive(Deserialize, Serialize, ToSchema)]
struct TwoFactorEnableRequest {
    #[schema(example = "supersecret123")]
    current_password: String,
    #[schema(example = "123456")]
    code: String,
}

#[derive(Deserialize, Serialize, ToSchema)]
struct TwoFactorDisableRequest {
    #[schema(example = "supersecret123")]
    current_password: String,
    #[schema(example = "123456")]
    code: String,
}

#[derive(Deserialize, Serialize, ToSchema)]
struct AuthLoginTwoFactorRequest {
    #[schema(example = "abc123")]
    challenge_token: String,
    #[schema(example = "123456")]
    code: String,
}

#[derive(Deserialize, Serialize, ToSchema)]
struct AuthLoginTwoFactorSetupRequest {
    #[schema(example = "abc123")]
    challenge_token: String,
}

#[derive(Deserialize, Serialize, ToSchema)]
struct ProfilePasswordRequest {
    #[schema(example = "oldpassword123")]
    current_password: String,
    #[schema(example = "newpassword123")]
    new_password: String,
    #[schema(example = "newpassword123")]
    password_confirm: String,
}

#[derive(Deserialize, Serialize, ToSchema)]
struct ProfileDeleteRequest {
    #[schema(example = "supersecret123")]
    password: String,
}

#[derive(Serialize, ToSchema)]
struct KeyRegenerateResponse {
    key: String,
}

#[derive(Serialize, ToSchema)]
struct RecoveryCodesResponse {
    recovery_codes: Vec<String>,
}

#[derive(Deserialize, Serialize, ToSchema)]
struct AuthPasswordResetRequest {
    #[schema(example = "alice")]
    username: String,
    #[schema(example = "9fd5aa184c1b")]
    recovery_code: String,
    #[schema(example = "newpassword123")]
    new_password: String,
    #[schema(example = "newpassword123")]
    password_confirm: String,
    #[schema(example = "cap_123")]
    captcha_id: String,
    #[schema(example = "7f3ca9")]
    captcha_answer: String,
}

#[derive(Deserialize, IntoParams, Serialize, ToSchema)]
struct UsersSearchParams {
    #[serde(default)]
    #[schema(example = "adm")]
    q: String,
    #[serde(default = "default_page")]
    #[schema(example = 1)]
    page: usize,
    #[serde(default = "default_limit")]
    #[schema(example = 25)]
    limit: usize,
}

#[derive(Deserialize, IntoParams, Serialize, ToSchema)]
struct UsernameCheckParams {
    #[schema(example = "alice")]
    username: String,
}

#[derive(Serialize, ToSchema)]
struct UsernameCheckResponse {
    normalized: String,
    valid: bool,
    available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize, ToSchema)]
struct UsersListResponse {
    items: Vec<AuthUserResponse>,
    page: usize,
    limit: usize,
    total_results: usize,
    has_next: bool,
}

#[derive(Deserialize, Serialize, ToSchema)]
struct AdminUserCreateRequest {
    #[schema(example = "alice")]
    username: String,
    #[schema(example = "supersecret123")]
    password: String,
    #[schema(example = "supersecret123")]
    password_confirm: String,
    #[schema(example = "user")]
    role: String,
}

#[derive(Serialize, ToSchema)]
struct AdminUserCreateResponse {
    user: AuthUserResponse,
    key: String,
    recovery_codes: Vec<String>,
}

#[derive(Deserialize, Serialize, ToSchema)]
struct AdminUserRoleRequest {
    #[schema(example = "alice")]
    username: String,
    #[schema(example = "admin")]
    role: String,
}

#[derive(Deserialize, Serialize, ToSchema)]
struct AdminUserNameRequest {
    #[schema(example = "alice")]
    username: String,
}

#[derive(Deserialize, Serialize, ToSchema)]
struct AdminUserTwoFactorRequiredRequest {
    #[schema(example = "alice")]
    username: String,
    #[schema(example = true)]
    required: bool,
}

#[derive(Deserialize, IntoParams, ToSchema)]
struct ProfilePictureParams {
    #[schema(example = "alice")]
    username: String,
}

#[derive(Deserialize, Serialize, ToSchema)]
struct AdminUserEnabledRequest {
    #[schema(example = "alice")]
    username: String,
    #[schema(example = false)]
    enabled: bool,
}

#[derive(Serialize, ToSchema)]
struct AdminPasswordResetResponse {
    username: String,
    password: String,
}

#[allow(dead_code)]
#[derive(ToSchema)]
struct UploadSampleRequestDoc {
    #[schema(value_type = String, format = Binary)]
    data: String,
    #[schema(example = "PE", nullable = true)]
    format: Option<String>,
    #[schema(example = "amd64", nullable = true)]
    architecture: Option<String>,
    #[schema(nullable = true)]
    corpus: Option<Vec<String>>,
}
