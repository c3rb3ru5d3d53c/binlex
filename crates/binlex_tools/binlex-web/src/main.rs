use axum::Json;
use axum::Router;
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Extension, Multipart, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode, header};
use axum::middleware;
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use binlex::clients::Server;
use binlex::controlflow::{BlockJson, FunctionJson, Graph, GraphSnapshot, InstructionJson};
use binlex::databases::{LocalDB, SampleStatus, SampleStatusRecord};
use binlex::indexing::{Collection, LocalIndex, SearchResult};
use binlex::math::similarity::cosine;
use binlex::search::{
    QueryCompletionSpec, query_architecture_values, query_collection_values,
    query_completion_specs, query_score_matches,
};
use binlex::server::request_id::RequestId;
use binlex::yara::Rule;
use binlex::{Architecture, Config, Magic};
use chrono::Utc;
use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io::Cursor;
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use tokio::task;
use tracing::{info, warn};
use utoipa::openapi::security::{ApiKey, ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::openapi::{ComponentsBuilder, InfoBuilder};
use utoipa::{IntoParams, Modify, OpenApi, ToSchema};
use utoipa_swagger_ui::SwaggerUi;
use zip::CompressionMethod;
use zip::ZipWriter;
use zip::unstable::write::FileOptionsExt;
use zip::write::FileOptions;

mod assets;
mod pages;
mod query;

use crate::pages::index::{display_architecture, render_page};
use crate::query::{
    CompareDirection, ExpandTarget, QuerySide, SearchRoot, StreamOp, StreamPlan, build_query_plan,
    search_expr_matches,
};

const DEFAULT_LISTEN: &str = "127.0.0.1";
const DEFAULT_PORT: u16 = 8000;
const DEFAULT_URL: &str = "http://127.0.0.1:8000";
const DEFAULT_SERVER_URL: &str = "http://127.0.0.1:5000";
const DEFAULT_TOP_K: usize = 16;
const MAX_TOP_K: usize = 64;
const DEFAULT_CORPUS: &str = "default";
const CONFIG_FILE_NAME: &str = "binlex-web.toml";

include!("includes/web_config.inc.rs");
include!("includes/web_state.inc.rs");
include!("includes/web_dto.inc.rs");
include!("includes/web_auth.inc.rs");
include!("includes/web_router.inc.rs");
include!("includes/web_helpers.inc.rs");
include!("includes/web_index.inc.rs");
include!("includes/web_tags.inc.rs");
include!("includes/web_search.inc.rs");
include!("includes/web_upload.inc.rs");
include!("includes/web_download.inc.rs");
include!("includes/web_test.inc.rs");
include!("includes/web_openapi_error.inc.rs");
include!("includes/web_startup.inc.rs");
