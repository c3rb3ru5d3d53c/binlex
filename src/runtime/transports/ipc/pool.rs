use std::collections::HashMap;
use std::io::ErrorKind;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use interprocess::local_socket::ListenerNonblockingMode;
use interprocess::local_socket::Stream;
use interprocess::local_socket::traits::{Listener as _, Stream as _};
use once_cell::sync::Lazy;

use crate::config::ConfigProcessors;
use crate::processor;
use crate::runtime::dispatch::{Processor, WorkerLaunch};
use crate::runtime::error::ProcessorError;
use crate::runtime::transports::ipc::local;
use crate::runtime::transports::ipc::protocol::{
    Hello, MessageKind, ProcessorFailure, read_frame, write_frame,
};

type PoolKey = (&'static str, String);

static POOLS: Lazy<Mutex<HashMap<PoolKey, Arc<ProcessorPool>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

struct ProcessorHandle {
    child: Child,
    stream: Stream,
    pid: u32,
}

pub struct ProcessorPool {
    config: ConfigProcessors,
    binary_name: String,
    launch: WorkerLaunch,
    processor_name: &'static str,
    processor_id: u16,
    timeout: Duration,
    processors: Vec<Mutex<ProcessorHandle>>,
    next_request_id: AtomicU64,
    next_processor: AtomicUsize,
}

impl ProcessorPool {
    pub fn new(
        config: ConfigProcessors,
        binary_name: impl Into<String>,
        processor_name: &'static str,
        processor_id: u16,
        launches: Vec<WorkerLaunch>,
    ) -> Result<Self, ProcessorError> {
        let binary_name = binary_name.into();
        let timeout = timeout_for_config(&config);
        let process_count = config.processes.max(1);
        let (launch, first_processor) = spawn_worker_with_fallback(
            launches,
            &binary_name,
            processor_name,
            processor_id,
            config.compression,
            timeout,
        )?;
        let mut processors = Vec::with_capacity(process_count);
        processors.push(Mutex::new(first_processor));
        for _ in 1..process_count {
            processors.push(Mutex::new(Self::spawn_worker(
                &binary_name,
                processor_name,
                processor_id,
                &launch,
                config.compression,
                timeout,
            )?));
        }
        Ok(Self {
            config,
            binary_name,
            launch,
            processor_name,
            processor_id,
            timeout,
            processors,
            next_request_id: AtomicU64::new(1),
            next_processor: AtomicUsize::new(0),
        })
    }

    pub fn execute<P: Processor>(
        &self,
        request: &P::Request,
    ) -> Result<P::Response, ProcessorError> {
        let payload = postcard::to_allocvec(request)?;
        if payload.len() > self.config.max_payload_bytes {
            return Err(ProcessorError::RequestTooLarge(payload.len()));
        }

        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let mut attempts = 0u32;
        let max_attempts = if self.config.restart_on_crash { 3 } else { 1 };

        loop {
            attempts += 1;
            let processor_index =
                self.next_processor.fetch_add(1, Ordering::Relaxed) % self.processors.len();
            let mut processor = self.lock_processor(processor_index)?;
            let response = self.send_request::<P>(&mut processor, request_id, &payload);

            match response {
                Ok(response) => return Ok(response),
                Err(error) if attempts < max_attempts && is_retryable(&error) => {
                    *processor = Self::spawn_worker(
                        &self.binary_name,
                        self.processor_name,
                        self.processor_id,
                        &self.launch,
                        self.config.compression,
                        self.timeout,
                    )?;
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub fn for_processor<P: Processor>(
        config: &ConfigProcessors,
    ) -> Result<Arc<Self>, ProcessorError> {
        let key = (
            P::NAME,
            toml::to_string(config).map_err(|error| ProcessorError::Protocol(error.to_string()))?,
        );
        let mut pools = POOLS
            .lock()
            .map_err(|_| ProcessorError::Protocol("processor pool mutex poisoned".to_string()))?;
        if let Some(pool) = pools.get(&key) {
            return Ok(Arc::clone(pool));
        }

        let binary_name = P::filename();
        let launches = P::launches(config)?;
        let registration = processor::processor_registration_by_type::<P>().ok_or_else(|| {
            ProcessorError::Protocol(format!("unregistered processor {}", P::NAME))
        })?;
        let pool = Arc::new(Self::new(
            config.clone(),
            binary_name,
            P::NAME,
            registration.id,
            launches,
        )?);
        pools.insert(key, Arc::clone(&pool));
        Ok(pool)
    }

    pub fn processor_pids(&self) -> Result<Vec<u32>, ProcessorError> {
        let mut pids = Vec::with_capacity(self.processors.len());
        for processor in &self.processors {
            let processor = processor
                .lock()
                .map_err(|_| ProcessorError::Protocol("processor mutex poisoned".to_string()))?;
            pids.push(processor.pid);
        }
        Ok(pids)
    }

    fn lock_processor(
        &self,
        processor_index: usize,
    ) -> Result<MutexGuard<'_, ProcessorHandle>, ProcessorError> {
        self.processors[processor_index]
            .lock()
            .map_err(|_| ProcessorError::Protocol("processor mutex poisoned".to_string()))
    }

    fn send_request<P: Processor>(
        &self,
        processor: &mut ProcessorHandle,
        request_id: u64,
        payload: &[u8],
    ) -> Result<P::Response, ProcessorError> {
        write_frame(
            &mut processor.stream,
            MessageKind::Request,
            self.processor_id,
            request_id,
            payload,
            self.config.compression,
        )
        .map_err(|error| map_timeout_error("send request", error))?;
        let frame = read_frame(&mut processor.stream)
            .map_err(|error| map_timeout_error("read response", error))?;
        if frame.header.request_id != request_id {
            return Err(ProcessorError::UnexpectedResponse(format!(
                "request id mismatch, expected {}, got {}",
                request_id, frame.header.request_id
            )));
        }
        if frame.header.id != self.processor_id {
            return Err(ProcessorError::UnexpectedResponse(format!(
                "processor id mismatch, expected {}, got {}",
                self.processor_id, frame.header.id
            )));
        }

        match frame.header.kind {
            MessageKind::Response => Ok(postcard::from_bytes(&frame.payload)?),
            MessageKind::Error => {
                let failure: ProcessorFailure = postcard::from_bytes(&frame.payload)?;
                Err(ProcessorError::RemoteFailure(failure.message))
            }
            other => Err(ProcessorError::UnexpectedResponse(format!(
                "unexpected processor message kind: {:?}",
                other
            ))),
        }
    }

    fn spawn_worker(
        binary_name: &str,
        processor_name: &str,
        processor_id: u16,
        launch: &WorkerLaunch,
        compression: bool,
        timeout: Duration,
    ) -> Result<ProcessorHandle, ProcessorError> {
        let (socket_name, listener) = local::bind_listener(binary_name)?;
        listener
            .set_nonblocking(ListenerNonblockingMode::Accept)
            .map_err(ProcessorError::Io)?;
        let mut child = command_for_launch(launch)
            .arg("--socket")
            .arg(&socket_name)
            .arg("--processor")
            .arg(processor_name)
            .arg("--compression")
            .arg(if compression { "true" } else { "false" })
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| ProcessorError::Spawn(error.to_string()))?;
        let mut stream = accept_with_timeout(&listener, &mut child, timeout)?;
        stream
            .set_recv_timeout(Some(timeout))
            .map_err(ProcessorError::Io)?;
        stream
            .set_send_timeout(Some(timeout))
            .map_err(ProcessorError::Io)?;
        let frame =
            read_frame(&mut stream).map_err(|error| map_timeout_error("read hello", error))?;
        if frame.header.kind != MessageKind::HelloAck {
            return Err(ProcessorError::UnexpectedResponse(
                "expected processor hello ack".to_string(),
            ));
        }
        let hello: Hello = postcard::from_bytes(&frame.payload)?;
        validate_hello(&hello, binary_name, processor_name, processor_id)?;
        Ok(ProcessorHandle {
            child,
            stream,
            pid: hello.pid,
        })
    }
}

fn spawn_worker_with_fallback(
    launches: Vec<WorkerLaunch>,
    binary_name: &str,
    processor_name: &str,
    processor_id: u16,
    compression: bool,
    timeout: Duration,
) -> Result<(WorkerLaunch, ProcessorHandle), ProcessorError> {
    let mut last_error = None;
    for launch in launches {
        match ProcessorPool::spawn_worker(
            binary_name,
            processor_name,
            processor_id,
            &launch,
            compression,
            timeout,
        ) {
            Ok(handle) => return Ok((launch, handle)),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        ProcessorError::Spawn("no processor launch candidates were available".to_string())
    }))
}

fn command_for_launch(launch: &WorkerLaunch) -> Command {
    match launch {
        WorkerLaunch::Binary(path) => Command::new(path),
        WorkerLaunch::Command(command) => {
            let mut iter = command.iter();
            let executable = iter
                .next()
                .expect("worker command launch must include an executable");
            let mut process = Command::new(executable);
            process.args(iter);
            process
        }
    }
}

fn is_retryable(error: &ProcessorError) -> bool {
    matches!(
        error,
        ProcessorError::Io(_)
            | ProcessorError::Protocol(_)
            | ProcessorError::Spawn(_)
            | ProcessorError::Timeout(_)
            | ProcessorError::UnexpectedResponse(_)
    )
}

fn timeout_for_config(config: &ConfigProcessors) -> Duration {
    Duration::from_millis(config.idle_timeout_ms.max(1))
}

fn map_timeout_error(context: &str, error: ProcessorError) -> ProcessorError {
    match error {
        ProcessorError::Io(error)
            if matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) =>
        {
            ProcessorError::Timeout(format!("{} timed out", context))
        }
        other => other,
    }
}

fn accept_with_timeout(
    listener: &interprocess::local_socket::Listener,
    child: &mut Child,
    timeout: Duration,
) -> Result<Stream, ProcessorError> {
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok(stream) => return Ok(stream),
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                if let Some(status) = child.try_wait().map_err(ProcessorError::Io)? {
                    return Err(ProcessorError::Spawn(format!(
                        "processor exited before connecting: {}",
                        status
                    )));
                }
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(ProcessorError::Timeout(
                        "processor startup timed out waiting for connection".to_string(),
                    ));
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(ProcessorError::Io(error)),
        }
    }
}

fn validate_hello(
    hello: &Hello,
    binary_name: &str,
    processor_name: &str,
    processor_id: u16,
) -> Result<(), ProcessorError> {
    let registration =
        processor::registry::processor_registration_by_name_unfiltered(processor_name).ok_or_else(
            || ProcessorError::Protocol(format!("unregistered processor {}", processor_name)),
        )?;
    if hello.protocol_version != crate::runtime::transports::ipc::protocol::VERSION {
        return Err(ProcessorError::UnexpectedResponse(format!(
            "processor protocol payload mismatch, expected {}, got {}",
            crate::runtime::transports::ipc::protocol::VERSION,
            hello.protocol_version
        )));
    }
    if hello.backend_name != binary_name {
        return Err(ProcessorError::UnexpectedResponse(format!(
            "processor backend mismatch, expected {}, got {}",
            binary_name, hello.backend_name
        )));
    }
    crate::processor::registry::ensure_version_requirement(
        &hello.binlex_version,
        registration.registration.requires,
    )?;
    if hello.processor_name != processor_name {
        return Err(ProcessorError::UnexpectedResponse(format!(
            "processor name mismatch, expected {}, got {}",
            processor_name, hello.processor_name
        )));
    }
    if !hello.supported_ids.contains(&processor_id) {
        return Err(ProcessorError::UnexpectedResponse(format!(
            "processor id {} not advertised by {}",
            processor_id, hello.processor_name
        )));
    }
    let processor = hello
        .processors
        .iter()
        .find(|processor| processor.id == processor_id)
        .ok_or_else(|| {
            ProcessorError::UnexpectedResponse(format!(
                "processor id {} metadata not advertised by {}",
                processor_id, hello.processor_name
            ))
        })?;
    if processor.name != processor_name {
        return Err(ProcessorError::UnexpectedResponse(format!(
            "processor metadata name mismatch for id {}, expected {}, got {}",
            processor_id, processor_name, processor.name
        )));
    }
    crate::processor::registry::ensure_version_requirement(crate::VERSION, &processor.requires)?;
    if !processor.os.contains(&hello.host_os) {
        return Err(ProcessorError::UnexpectedResponse(format!(
            "processor {} on host {:?} advertised unsupported os list {:?}",
            processor.name, hello.host_os, processor.os
        )));
    }
    Ok(())
}

impl Drop for ProcessorHandle {
    fn drop(&mut self) {
        let _ = write_frame(&mut self.stream, MessageKind::Shutdown, 0, 0, &[], false);
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::validate_hello;
    use crate::processor::ProcessorOs;
    use crate::runtime::transports::ipc::protocol::{Hello, HelloProcessor, VERSION};

    #[test]
    fn validate_hello_accepts_matching_os_negotiation() {
        let hello = Hello {
            protocol_version: VERSION,
            backend_name: "binlex-processor-embeddings".to_string(),
            binlex_version: crate::VERSION.to_string(),
            host_os: ProcessorOs::current(),
            processor_name: "embeddings".to_string(),
            supported_ids: vec![1],
            processors: vec![HelloProcessor {
                id: 1,
                name: "embeddings".to_string(),
                requires: ">=2.0.0 <3.0.0".to_string(),
                os: vec![ProcessorOs::current()],
            }],
            pid: 1,
        };

        assert!(validate_hello(&hello, "binlex-processor-embeddings", "embeddings", 1).is_ok());
    }

    #[test]
    fn validate_hello_rejects_processor_os_mismatch() {
        let unsupported = match ProcessorOs::current() {
            ProcessorOs::Linux => ProcessorOs::Windows,
            ProcessorOs::Macos => ProcessorOs::Windows,
            ProcessorOs::Windows => ProcessorOs::Linux,
        };
        let hello = Hello {
            protocol_version: VERSION,
            backend_name: "binlex-processor-embeddings".to_string(),
            binlex_version: crate::VERSION.to_string(),
            host_os: ProcessorOs::current(),
            processor_name: "embeddings".to_string(),
            supported_ids: vec![1],
            processors: vec![HelloProcessor {
                id: 1,
                name: "embeddings".to_string(),
                requires: ">=2.0.0 <3.0.0".to_string(),
                os: vec![unsupported],
            }],
            pid: 1,
        };

        let error = validate_hello(&hello, "binlex-processor-embeddings", "embeddings", 1)
            .expect_err("hello should be rejected when processor os metadata excludes host os");
        assert!(error.to_string().contains("advertised unsupported os list"));
    }
}
