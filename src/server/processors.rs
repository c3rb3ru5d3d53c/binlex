use crate::config::ConfigProcessor;
use crate::processor::{ProcessorTransport, processor_registration_by_name_for_config};
use crate::server::dto::ProcessorHttpRequest;
use crate::server::error::ServerError;
use crate::server::state::AppState;
use serde_json::Value;

pub fn configured_server_transport(
    processor: &ConfigProcessor,
    supported: &[ProcessorTransport],
) -> Result<ProcessorTransport, ServerError> {
    if processor.transport.ipc.enabled && supported.contains(&ProcessorTransport::Ipc) {
        return Ok(ProcessorTransport::Ipc);
    }
    Err(ServerError::processor(
        "processor has no enabled server execution transport".to_string(),
    ))
}

pub fn execute(
    state: &AppState,
    processor_name: &str,
    request: ProcessorHttpRequest,
) -> Result<Value, ServerError> {
    if !state.processor_enabled(processor_name) {
        return Err(ServerError::processor(format!(
            "processor {} is disabled on this server",
            processor_name
        )));
    }

    let registration =
        processor_registration_by_name_for_config(&state.config.processors, processor_name)
            .ok_or_else(|| {
                ServerError::processor(format!("unsupported HTTP processor: {}", processor_name))
            })?;
    crate::processor::registry::ensure_registration_host_compatibility(&registration.registration)
        .map_err(ServerError::from)?;
    crate::processor::registry::ensure_version_requirement(
        &request.binlex_version,
        &registration.registration.requires,
    )
    .map_err(ServerError::from)?;
    crate::processor::registry::ensure_version_requirement(crate::VERSION, &request.requires)
        .map_err(ServerError::from)?;
    crate::processor::registry::ensure_payload_architecture_supported_server(
        &registration.registration,
        &request.data,
    )?;
    let processor = state
        .config
        .processors
        .processor(processor_name)
        .ok_or_else(|| {
            ServerError::processor(format!("processor {} is not configured", processor_name))
        })?;
    match configured_server_transport(processor, &registration.registration.transports)? {
        ProcessorTransport::Ipc => {
            let pool = state.processor_pool(processor_name).ok_or_else(|| {
                ServerError::processor(format!(
                    "processor {} pool is not available",
                    processor_name
                ))
            })?;
            let response = pool
                .execute_json(&crate::runtime::JsonProcessorRequest {
                    config: toml::to_string(&state.config.processors)
                        .map_err(|error| ServerError::processor(error.to_string()))?,
                    data: serde_json::to_string(&request.data)
                        .map_err(|error| ServerError::processor(error.to_string()))?,
                })
                .map_err(ServerError::from)?;
            serde_json::from_str(&response.data)
                .map_err(|error| ServerError::processor(error.to_string()))
        }
        ProcessorTransport::Http => Err(ServerError::processor(format!(
            "processor {} server transport cannot be http",
            processor_name
        ))),
    }
}
