use std::sync::Arc;
use std::time::Duration;

use actix_web::{App, HttpServer, web};
use rmcp::handler::server::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    GetPromptRequestParams, GetPromptResult, ListPromptsResult, PaginatedRequestParams,
    ServerCapabilities, ServerInfo,
};
use rmcp::service::RequestContext;
use rmcp::{RoleServer, ServerHandler, tool, tool_handler, tool_router};
use rmcp_actix_web::transport::StreamableHttpService;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use tracing::info;

use crate::error::internal_error;
use crate::python::{PythonRequest, execute_python};
use crate::samples::{SampleGetRequest, SamplePutRequest, download_bytes, upload_bytes};
use crate::skills::SkillPrompt;
use crate::state::{McpState, to_json_string};

#[derive(Clone)]
pub struct BinlexMcpServer {
    pub state: Arc<McpState>,
    pub tool_router: ToolRouter<Self>,
    pub prompts: Vec<SkillPrompt>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ProcessorRunRequest {
    pub processor: String,
    #[schemars(description = "JSON payload sent directly to the selected processor.")]
    pub data: Value,
}

#[derive(Serialize)]
struct McpInfoResponse {
    listen: String,
    port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    base_url: Option<String>,
    bind_url: String,
    effective_base_url: String,
}

impl BinlexMcpServer {
    pub fn new(state: McpState) -> Self {
        let prompts = state
            .mcp
            .skills
            .iter()
            .map(SkillPrompt::from_config)
            .collect();
        Self {
            state: Arc::new(state),
            tool_router: Self::tool_router(),
            prompts,
        }
    }

    pub async fn serve(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let bind = format!("{}:{}", self.state.mcp.listen, self.state.mcp.port);
        let sample_store = self.state.sample_store.clone();
        let max_upload_size_bytes = self.state.mcp.samples.max_upload_size_bytes;
        let service = StreamableHttpService::builder()
            .service_factory(Arc::new({
                let server = self.clone();
                move || Ok(server.clone())
            }))
            .session_manager(Arc::new(
                rmcp::transport::streamable_http_server::session::local::LocalSessionManager::default(),
            ))
            .stateful_mode(true)
            .sse_keep_alive(Duration::from_secs(30))
            .build();

        HttpServer::new(move || {
            App::new()
                .app_data(web::Data::from(sample_store.clone()))
                .app_data(web::PayloadConfig::new(max_upload_size_bytes))
                .route("/samples/uploads/{token}", web::put().to(upload_bytes))
                .route("/samples/{sha256}", web::get().to(download_bytes))
                .service(web::scope("/").service(service.clone().scope()))
        })
        .bind(bind)?
        .run()
        .await?;
        Ok(())
    }

    fn join_url(&self, path: &str) -> String {
        format!("{}{}", self.state.effective_base_url(), path)
    }
}

#[tool_router]
impl BinlexMcpServer {
    #[tool(
        name = "python",
        description = "Execute Python in the active environment with Binlex bindings available."
    )]
    fn python(
        &self,
        Parameters(request): Parameters<PythonRequest>,
    ) -> Result<String, rmcp::ErrorData> {
        let response = execute_python(&self.state.python_command, request)
            .map_err(|error| internal_error(error.to_string()))?;
        to_json_string(&response).map_err(|error| internal_error(error.to_string()))
    }

    #[tool(
        name = "processors.list",
        description = "List the external Binlex processors discoverable for this configuration."
    )]
    fn processors_list(&self) -> Result<String, rmcp::ErrorData> {
        to_json_string(&self.state.processor_list())
            .map_err(|error| internal_error(error.to_string()))
    }

    #[tool(
        name = "processors.run",
        description = "Execute an external Binlex processor with a JSON payload."
    )]
    fn processors_run(
        &self,
        Parameters(request): Parameters<ProcessorRunRequest>,
    ) -> Result<String, rmcp::ErrorData> {
        let value = self
            .state
            .processor_run(&request.processor, request.data)
            .map_err(|error| internal_error(error.to_string()))?;
        to_json_string(&value).map_err(|error| internal_error(error.to_string()))
    }

    #[tool(
        name = "config.get",
        description = "Return the effective Binlex configuration."
    )]
    fn config_get(&self) -> Result<String, rmcp::ErrorData> {
        to_json_string(&self.state.config).map_err(|error| internal_error(error.to_string()))
    }

    #[tool(
        name = "mcp.info",
        description = "Return the effective Binlex MCP listener and advertised base URL."
    )]
    fn mcp_info(&self) -> Result<String, rmcp::ErrorData> {
        to_json_string(&McpInfoResponse {
            listen: self.state.mcp.listen.clone(),
            port: self.state.mcp.port,
            base_url: self.state.mcp.base_url.clone(),
            bind_url: self.state.bind_url(),
            effective_base_url: self.state.effective_base_url(),
        })
        .map_err(|error| internal_error(error.to_string()))
    }

    #[tool(
        name = "samples.put",
        description = "Prepare a direct upload into the server sample store and return the upload endpoint. The follow-up HTTP PUT should be performed outside the sandbox."
    )]
    fn samples_put(
        &self,
        Parameters(request): Parameters<SamplePutRequest>,
    ) -> Result<String, rmcp::ErrorData> {
        let mut response = self
            .state
            .sample_store
            .create_upload(request.filename)
            .map_err(|error| internal_error(error.to_string()))?;
        response.upload_url = Some(self.join_url(&response.upload_path));
        to_json_string(&response).map_err(|error| internal_error(error.to_string()))
    }

    #[tool(
        name = "samples.get",
        description = "Return the relative download endpoint for a stored sample identified by sha256."
    )]
    fn samples_get(
        &self,
        Parameters(request): Parameters<SampleGetRequest>,
    ) -> Result<String, rmcp::ErrorData> {
        let mut response = self
            .state
            .sample_store
            .get_download(&request.sha256)
            .map_err(|error| internal_error(error.to_string()))?;
        response.download_url = Some(self.join_url(&response.download_path));
        to_json_string(&response).map_err(|error| internal_error(error.to_string()))
    }
}

#[tool_handler]
impl ServerHandler for BinlexMcpServer {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.capabilities = ServerCapabilities::builder()
            .enable_tools()
            .enable_prompts()
            .build();
        info.instructions = Some(
            "Binlex MCP is Python-centered. Use samples.put and samples.get to negotiate direct sample transfer, then use the python tool or processor tools for analysis."
                .to_string(),
        );
        info
    }

    async fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, rmcp::ErrorData> {
        let mut result = ListPromptsResult::default();
        result.prompts = self
            .prompts
            .iter()
            .map(|prompt| prompt.prompt.clone())
            .collect();
        Ok(result)
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResult, rmcp::ErrorData> {
        let goal = request
            .arguments
            .as_ref()
            .and_then(|arguments| arguments.get("goal"))
            .and_then(Value::as_str);
        info!(
            skill = %request.name,
            has_goal = goal.is_some(),
            goal_len = goal.map_or(0, str::len),
            "skill prompt requested"
        );
        self.prompts
            .iter()
            .find(|prompt| prompt.prompt.name == request.name)
            .map(|prompt| prompt.render(goal))
            .ok_or_else(|| internal_error(format!("unknown prompt: {}", request.name)))
    }
}
