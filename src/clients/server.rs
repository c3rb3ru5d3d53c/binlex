use super::{Error, decode_response, normalize_url};
use crate::controlflow::{BlockJson, FunctionJson, Graph, GraphSnapshot, InstructionJson};
use crate::indexing::Collection;
use crate::server::dto::{
    AnalyzeRequest, AnalyzeResponse, HealthResponse, LZ4_CONTENT_ENCODING,
    OCTET_STREAM_CONTENT_TYPE, ProcessEntityRequest, ProcessGraphRequest, ProcessorHttpRequest,
};
use crate::server::request_id::X_REQUEST_ID;
use base64::Engine;
use reqwest::blocking::Client as HttpClient;
use reqwest::header::{ACCEPT, CONTENT_ENCODING, CONTENT_TYPE, HeaderName};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;
use std::time::Duration;

const SERVER_VERSION_PATH: &str = "/api/v1/version";
const SERVER_PROCESSORS_PREFIX: &str = "/api/v1/processors/";

#[derive(Clone)]
pub struct Server {
    config: crate::Config,
    url: String,
    verify: bool,
    compression: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ServerVersionResponse {
    pub version: String,
}

impl Server {
    pub fn new(
        config: crate::Config,
        url: Option<String>,
        verify: Option<bool>,
        compression: Option<bool>,
    ) -> Result<Self, Error> {
        let url = normalize_url(url.unwrap_or_else(|| default_url(&config)))?;
        let compression = compression.unwrap_or(config_processors_compression(&config));
        Ok(Self {
            config,
            url,
            verify: verify.unwrap_or(true),
            compression,
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn verify(&self) -> bool {
        self.verify
    }

    pub fn compression(&self) -> bool {
        self.compression
    }

    pub fn version(&self) -> Result<ServerVersionResponse, Error> {
        self.version_with_request_id(None)
    }

    pub fn version_with_request_id(
        &self,
        request_id: Option<&str>,
    ) -> Result<ServerVersionResponse, Error> {
        let client = self.http_client()?;
        let mut builder = client
            .get(format!("{}{}", self.url, SERVER_VERSION_PATH))
            .header(ACCEPT, "application/json");
        if let Some(request_id) = request_id {
            builder = builder.header(HeaderName::from_static(X_REQUEST_ID), request_id);
        }
        let response = builder
            .send()
            .map_err(|error| Error::Io(error.to_string()))?;
        decode_response(response)
    }

    pub fn health(&self) -> Result<HealthResponse, Error> {
        self.health_with_request_id(None)
    }

    pub fn health_with_request_id(
        &self,
        request_id: Option<&str>,
    ) -> Result<HealthResponse, Error> {
        let client = self.http_client()?;
        let mut builder = client
            .get(format!("{}/api/v1/health", self.url))
            .header(ACCEPT, "application/json");
        if let Some(request_id) = request_id {
            builder = builder.header(HeaderName::from_static(X_REQUEST_ID), request_id);
        }
        let response = builder
            .send()
            .map_err(|error| Error::Io(error.to_string()))?;
        decode_response(response)
    }

    pub fn analyze_file(
        &self,
        path: impl AsRef<Path>,
        magic: Option<crate::Magic>,
        architecture: Option<crate::Architecture>,
    ) -> Result<Graph, Error> {
        let path = path.as_ref();
        let data = std::fs::read(path).map_err(|error| Error::Io(error.to_string()))?;
        self.analyze_bytes(&data, magic, architecture)
    }

    pub fn analyze_bytes(
        &self,
        data: &[u8],
        magic: Option<crate::Magic>,
        architecture: Option<crate::Architecture>,
    ) -> Result<Graph, Error> {
        self.analyze_bytes_with_corpora(data, magic, architecture, &[])
    }

    pub fn analyze_bytes_with_corpora(
        &self,
        data: &[u8],
        magic: Option<crate::Magic>,
        architecture: Option<crate::Architecture>,
        corpora: &[String],
    ) -> Result<Graph, Error> {
        self.analyze_bytes_with_corpora_and_request_id(data, magic, architecture, corpora, None)
    }

    pub fn analyze_bytes_with_corpora_and_request_id(
        &self,
        data: &[u8],
        magic: Option<crate::Magic>,
        architecture: Option<crate::Architecture>,
        corpora: &[String],
        request_id: Option<&str>,
    ) -> Result<Graph, Error> {
        let response = self.analyze_bytes_response_with_corpora_collections_and_request_id(
            data,
            magic,
            architecture,
            corpora,
            &[],
            request_id,
        )?;
        Graph::from_snapshot(response.snapshot, self.config.clone())
            .map_err(|error| Error::Graph(error.to_string()))
    }

    pub fn analyze_bytes_response_with_corpora_and_request_id(
        &self,
        data: &[u8],
        magic: Option<crate::Magic>,
        architecture: Option<crate::Architecture>,
        corpora: &[String],
        request_id: Option<&str>,
    ) -> Result<AnalyzeResponse, Error> {
        self.analyze_bytes_response_with_corpora_collections_and_request_id(
            data,
            magic,
            architecture,
            corpora,
            &[],
            request_id,
        )
    }

    pub fn analyze_bytes_response_with_corpora_collections_and_request_id(
        &self,
        data: &[u8],
        magic: Option<crate::Magic>,
        architecture: Option<crate::Architecture>,
        corpora: &[String],
        collections: &[Collection],
        request_id: Option<&str>,
    ) -> Result<AnalyzeResponse, Error> {
        let request = AnalyzeRequest {
            data: base64::engine::general_purpose::STANDARD.encode(data),
            magic: magic.map(|value| value.to_string()),
            architecture: architecture.map(|value| value.to_string()),
            corpora: corpora.to_vec(),
            collections: collections.to_vec(),
        };
        let client = self.http_client()?;
        let body = encode_request(&request, self.compression)?;
        let mut builder = client
            .post(format!("{}/api/v1/analyze", self.url))
            .header(
                CONTENT_TYPE,
                if self.compression {
                    OCTET_STREAM_CONTENT_TYPE
                } else {
                    "application/json"
                },
            )
            .header(
                ACCEPT,
                if self.compression {
                    OCTET_STREAM_CONTENT_TYPE
                } else {
                    "application/json"
                },
            );
        if self.compression {
            builder = builder.header(CONTENT_ENCODING, LZ4_CONTENT_ENCODING);
        }
        if let Some(request_id) = request_id {
            builder = builder.header(HeaderName::from_static(X_REQUEST_ID), request_id);
        }
        let response = builder
            .body(body)
            .send()
            .map_err(|error| Error::Io(error.to_string()))?;
        decode_response(response)
    }

    pub fn process_graph(&self, graph: &Graph) -> Result<Graph, Error> {
        self.process_graph_with_request_id(graph, None)
    }

    pub fn process_graph_with_request_id(
        &self,
        graph: &Graph,
        request_id: Option<&str>,
    ) -> Result<Graph, Error> {
        self.process_snapshot_with_request_id(graph.snapshot(), request_id)
    }

    pub fn process_snapshot(&self, snapshot: GraphSnapshot) -> Result<Graph, Error> {
        self.process_snapshot_with_request_id(snapshot, None)
    }

    pub fn process_snapshot_with_request_id(
        &self,
        snapshot: GraphSnapshot,
        request_id: Option<&str>,
    ) -> Result<Graph, Error> {
        let request = ProcessGraphRequest { graph: snapshot };
        let client = self.http_client()?;
        let body = encode_request(&request, self.compression)?;
        let mut builder = client
            .post(format!("{}/api/v1/process", self.url))
            .header(
                CONTENT_TYPE,
                if self.compression {
                    OCTET_STREAM_CONTENT_TYPE
                } else {
                    "application/json"
                },
            )
            .header(
                ACCEPT,
                if self.compression {
                    OCTET_STREAM_CONTENT_TYPE
                } else {
                    "application/json"
                },
            );
        if self.compression {
            builder = builder.header(CONTENT_ENCODING, LZ4_CONTENT_ENCODING);
        }
        if let Some(request_id) = request_id {
            builder = builder.header(HeaderName::from_static(X_REQUEST_ID), request_id);
        }
        let response = builder
            .body(body)
            .send()
            .map_err(|error| Error::Io(error.to_string()))?;
        let processed: GraphSnapshot = decode_response(response)?;
        Graph::from_snapshot(processed, self.config.clone())
            .map_err(|error| Error::Graph(error.to_string()))
    }

    pub fn process_function_json(&self, function: FunctionJson) -> Result<FunctionJson, Error> {
        self.process_function_json_with_request_id(function, None)
    }

    pub fn process_function_json_with_request_id(
        &self,
        function: FunctionJson,
        request_id: Option<&str>,
    ) -> Result<FunctionJson, Error> {
        match self.process_entity_with_request_id(
            ProcessEntityRequest::Function { function },
            request_id,
        )? {
            ProcessEntityResponse::Function(function) => Ok(function),
            _ => Err(Error::Protocol(
                "server returned unexpected entity variant for function".to_string(),
            )),
        }
    }

    pub fn process_block_json(&self, block: BlockJson) -> Result<BlockJson, Error> {
        self.process_block_json_with_request_id(block, None)
    }

    pub fn process_block_json_with_request_id(
        &self,
        block: BlockJson,
        request_id: Option<&str>,
    ) -> Result<BlockJson, Error> {
        match self
            .process_entity_with_request_id(ProcessEntityRequest::Block { block }, request_id)?
        {
            ProcessEntityResponse::Block(block) => Ok(block),
            _ => Err(Error::Protocol(
                "server returned unexpected entity variant for block".to_string(),
            )),
        }
    }

    pub fn process_instruction_json(
        &self,
        instruction: InstructionJson,
    ) -> Result<InstructionJson, Error> {
        self.process_instruction_json_with_request_id(instruction, None)
    }

    pub fn process_instruction_json_with_request_id(
        &self,
        instruction: InstructionJson,
        request_id: Option<&str>,
    ) -> Result<InstructionJson, Error> {
        match self.process_entity_with_request_id(
            ProcessEntityRequest::Instruction { instruction },
            request_id,
        )? {
            ProcessEntityResponse::Instruction(instruction) => Ok(instruction),
            _ => Err(Error::Protocol(
                "server returned unexpected entity variant for instruction".to_string(),
            )),
        }
    }

    fn process_entity_with_request_id(
        &self,
        request: ProcessEntityRequest,
        request_id: Option<&str>,
    ) -> Result<ProcessEntityResponse, Error> {
        let client = self.http_client()?;
        let body = encode_request(&request, self.compression)?;
        let mut builder = client
            .post(format!("{}/api/v1/process/entity", self.url))
            .header(
                CONTENT_TYPE,
                if self.compression {
                    OCTET_STREAM_CONTENT_TYPE
                } else {
                    "application/json"
                },
            )
            .header(
                ACCEPT,
                if self.compression {
                    OCTET_STREAM_CONTENT_TYPE
                } else {
                    "application/json"
                },
            );
        if self.compression {
            builder = builder.header(CONTENT_ENCODING, LZ4_CONTENT_ENCODING);
        }
        if let Some(request_id) = request_id {
            builder = builder.header(HeaderName::from_static(X_REQUEST_ID), request_id);
        }
        let response = builder
            .body(body)
            .send()
            .map_err(|error| Error::Io(error.to_string()))?;
        decode_response(response)
    }

    pub fn execute_processor(
        &self,
        processor: &str,
        binlex_version: &str,
        requires: &str,
        data: Value,
    ) -> Result<Value, Error> {
        self.execute_processor_with_request_id(processor, binlex_version, requires, data, None)
    }

    pub fn execute_processor_with_request_id(
        &self,
        processor: &str,
        binlex_version: &str,
        requires: &str,
        data: Value,
        request_id: Option<&str>,
    ) -> Result<Value, Error> {
        let request = ProcessorHttpRequest {
            binlex_version: binlex_version.to_string(),
            requires: requires.to_string(),
            data,
        };
        let client = self.http_client()?;
        let body = encode_request(&request, self.compression)?;
        let mut builder = client
            .post(format!(
                "{}{SERVER_PROCESSORS_PREFIX}{}",
                self.url, processor
            ))
            .header(
                CONTENT_TYPE,
                if self.compression {
                    OCTET_STREAM_CONTENT_TYPE
                } else {
                    "application/json"
                },
            )
            .header(
                ACCEPT,
                if self.compression {
                    OCTET_STREAM_CONTENT_TYPE
                } else {
                    "application/json"
                },
            );
        if self.compression {
            builder = builder.header(CONTENT_ENCODING, LZ4_CONTENT_ENCODING);
        }
        if let Some(request_id) = request_id {
            builder = builder.header(HeaderName::from_static(X_REQUEST_ID), request_id);
        }
        let response = builder
            .body(body)
            .send()
            .map_err(|error| Error::Io(error.to_string()))?;
        decode_response(response)
    }

    fn http_client(&self) -> Result<HttpClient, Error> {
        HttpClient::builder()
            .danger_accept_invalid_certs(!self.verify)
            .user_agent(format!("binlex/{}", crate::VERSION))
            .timeout(Duration::from_secs(300))
            .build()
            .map_err(|error| Error::Protocol(error.to_string()))
    }
}

fn default_url(config: &crate::Config) -> String {
    let _ = config;
    "http://127.0.0.1:5000".to_string()
}

fn config_processors_compression(config: &crate::Config) -> bool {
    config.processors.compression
}

fn encode_request<T: Serialize>(request: &T, compression: bool) -> Result<Vec<u8>, Error> {
    let json =
        serde_json::to_vec(request).map_err(|error| Error::Serialization(error.to_string()))?;
    if !compression {
        return Ok(json);
    }
    let compressed = lz4::block::compress(&json, None, false)
        .map_err(|error| Error::Compression(error.to_string()))?;
    let mut payload = Vec::with_capacity(4 + compressed.len());
    payload.extend_from_slice(&(json.len() as u32).to_le_bytes());
    payload.extend_from_slice(&compressed);
    Ok(payload)
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum ProcessEntityResponse {
    Function(FunctionJson),
    Block(BlockJson),
    Instruction(InstructionJson),
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn server_route_constants_match_current_api() {
        assert_eq!(SERVER_VERSION_PATH, "/api/v1/version");
        assert_eq!(SERVER_PROCESSORS_PREFIX, "/api/v1/processors/");
    }
}
