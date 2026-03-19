use crate::Config;
use crate::config::ConfigProcessor;
use crate::processor::{ProcessorMode, processor_registration_by_name};
use crate::runtime::ProcessorError;
use crate::server::dto::{
    ErrorResponse, LZ4_CONTENT_ENCODING, OCTET_STREAM_CONTENT_TYPE, ProcessorHttpRequest,
};
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, CONTENT_ENCODING, CONTENT_TYPE};
use serde_json::Value;

fn processor_http_url(
    processor_name: &str,
    config: &ConfigProcessor,
) -> Result<String, ProcessorError> {
    let base_url = config
        .transport_string(ProcessorMode::Http, "url")
        .ok_or_else(|| {
            ProcessorError::Protocol(format!(
                "processor {} http mode requires url option",
                processor_name
            ))
        })?;
    Ok(format!(
        "{}/processors/{}",
        base_url.trim_end_matches('/'),
        processor_name
    ))
}

fn processor_http_verify(config: &ConfigProcessor) -> bool {
    config
        .transport_bool(ProcessorMode::Http, "verify")
        .unwrap_or(true)
}

fn encode_http_request(
    request: &ProcessorHttpRequest,
    compression_enabled: bool,
) -> Result<(Vec<u8>, &'static str), ProcessorError> {
    let json = serde_json::to_vec(request)
        .map_err(|error| ProcessorError::Serialization(error.to_string()))?;
    if !compression_enabled {
        return Ok((json, "application/json"));
    }

    let compressed = lz4::block::compress(&json, None, false)
        .map_err(|error| ProcessorError::Compression(error.to_string()))?;
    let mut payload = Vec::with_capacity(4 + compressed.len());
    payload.extend_from_slice(&(json.len() as u32).to_le_bytes());
    payload.extend_from_slice(&compressed);
    Ok((payload, OCTET_STREAM_CONTENT_TYPE))
}

fn decode_http_response(response: reqwest::blocking::Response) -> Result<Value, ProcessorError> {
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .bytes()
        .map_err(|error| ProcessorError::Io(std::io::Error::other(error.to_string())))?;

    if !status.is_success() {
        if let Ok(error) = serde_json::from_slice::<ErrorResponse>(&body) {
            return Err(ProcessorError::RemoteFailure(error.error));
        }
        return Err(ProcessorError::RemoteFailure(
            String::from_utf8_lossy(&body).into_owned(),
        ));
    }

    let decoded = if headers
        .get(CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case(LZ4_CONTENT_ENCODING))
    {
        if body.len() < 4 {
            return Err(ProcessorError::Compression(
                "compressed response missing size prefix".to_string(),
            ));
        }
        let uncompressed_len = u32::from_le_bytes([body[0], body[1], body[2], body[3]]) as i32;
        lz4::block::decompress(&body[4..], Some(uncompressed_len))
            .map_err(|error| ProcessorError::Compression(error.to_string()))?
    } else {
        body.to_vec()
    };

    serde_json::from_slice(&decoded)
        .map_err(|error| ProcessorError::Serialization(error.to_string()))
}

pub fn execute(
    processor_name: &str,
    data: Value,
    config: &Config,
    processor: &ConfigProcessor,
) -> Result<Value, ProcessorError> {
    let url = processor_http_url(processor_name, processor)?;
    let registration = processor_registration_by_name(processor_name).ok_or_else(|| {
        ProcessorError::Protocol(format!("processor {} is not registered", processor_name))
    })?;
    crate::processor::registry::ensure_registration_host_compatibility(registration.registration)?;
    let verify = processor_http_verify(processor);
    let client = Client::builder()
        .danger_accept_invalid_certs(!verify)
        .build()
        .map_err(|error| ProcessorError::Protocol(error.to_string()))?;
    let request = ProcessorHttpRequest {
        binlex_version: crate::VERSION.to_string(),
        requires: registration.registration.requires.to_string(),
        data,
    };
    let (body, content_type) = encode_http_request(&request, config.processors.compression)?;

    let mut builder = client
        .post(url)
        .header(CONTENT_TYPE, content_type)
        .header(ACCEPT, "application/json");

    if config.processors.compression {
        builder = builder
            .header(CONTENT_ENCODING, LZ4_CONTENT_ENCODING)
            .header(ACCEPT, OCTET_STREAM_CONTENT_TYPE);
    }

    let response = builder
        .body(body)
        .send()
        .map_err(|error| ProcessorError::Io(std::io::Error::other(error.to_string())))?;

    decode_http_response(response)
}
