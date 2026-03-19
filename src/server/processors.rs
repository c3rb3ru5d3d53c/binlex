use crate::config::ConfigProcessor;
use crate::processor::{JsonProcessor, ProcessorMode, processor_registration_by_name};
use crate::server::dto::ProcessorHttpRequest;
use crate::server::error::ServerError;
use crate::server::state::AppState;
use serde_json::Value;

pub fn configured_execution_mode(
    processor: &ConfigProcessor,
    supported: &[ProcessorMode],
) -> Result<ProcessorMode, ServerError> {
    if processor.inline.enabled && supported.contains(&ProcessorMode::Inline) {
        return Ok(ProcessorMode::Inline);
    }
    if processor.ipc.enabled && supported.contains(&ProcessorMode::Ipc) {
        return Ok(ProcessorMode::Ipc);
    }
    Err(ServerError::Processor(
        "processor has no enabled server execution transport".to_string(),
    ))
}

pub fn execute_value<P: JsonProcessor>(
    state: &AppState,
    data: Value,
) -> Result<Value, ServerError> {
    let processor = state.config.processors.processor(P::NAME).ok_or_else(|| {
        ServerError::Processor(format!("{} processor is not configured", P::NAME))
    })?;
    let registration = processor_registration_by_name(P::NAME).ok_or_else(|| {
        ServerError::Processor(format!("{} processor is not registered", P::NAME))
    })?;
    crate::processor::registry::ensure_payload_architecture_supported_server(
        registration.registration,
        &data,
    )?;
    match configured_execution_mode(processor, registration.registration.modes)? {
        ProcessorMode::Inline => {
            crate::runtime::modes::inline::execute::<P, crate::Config>(&state.config, data)
                .map_err(ServerError::from)
        }
        ProcessorMode::Ipc => {
            let response = if let Some(pool) = state.processor_pool(P::NAME) {
                crate::runtime::modes::ipc::execute_with_pool::<P, crate::Config>(
                    &pool,
                    &state.config,
                    data,
                )
            } else {
                crate::runtime::modes::ipc::execute::<P, crate::Config>(&state.config, data)
            };
            response.map_err(ServerError::from)
        }
        ProcessorMode::Http => Err(ServerError::Processor(format!(
            "processor {} server mode cannot be http",
            P::NAME
        ))),
    }
}

pub fn execute(
    state: &AppState,
    processor_name: &str,
    request: ProcessorHttpRequest,
) -> Result<Value, ServerError> {
    if !state.processor_enabled(processor_name) {
        return Err(ServerError::Processor(format!(
            "processor {} is disabled on this server",
            processor_name
        )));
    }

    let registration = processor_registration_by_name(processor_name).ok_or_else(|| {
        ServerError::Processor(format!("unsupported HTTP processor: {}", processor_name))
    })?;
    if !registration.registration.supports_mode("http") {
        return Err(ServerError::Processor(format!(
            "processor {} does not support HTTP mode",
            processor_name
        )));
    }
    crate::processor::registry::ensure_payload_architecture_supported_server(
        registration.registration,
        &request.data,
    )?;
    let execute = registration.registration.execute_value.ok_or_else(|| {
        ServerError::Processor(format!(
            "processor {} does not implement value execution",
            processor_name
        ))
    })?;
    execute(state, request.data)
}
