use std::collections::HashMap;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use interprocess::local_socket::Stream;
use interprocess::local_socket::traits::Listener as _;
use once_cell::sync::Lazy;

use crate::ConfigProcessors;
use crate::processing::error::ProcessorError;
use crate::processing::processor::Processor;
use crate::processing::protocol::{Hello, MessageKind, ProcessorFailure, read_frame, write_frame};
use crate::processing::transport;

type PoolKey = (&'static str, ConfigProcessors);

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
    processor_name: &'static str,
    processors: Vec<Mutex<ProcessorHandle>>,
    next_request_id: AtomicU64,
    next_processor: AtomicUsize,
}

impl ProcessorPool {
    pub fn new(
        config: ConfigProcessors,
        binary_name: impl Into<String>,
        processor_name: &'static str,
        spawn_path: impl AsRef<std::path::Path>,
    ) -> Result<Self, ProcessorError> {
        let binary_name = binary_name.into();
        let process_count = config.processes.max(1);
        let mut processors = Vec::with_capacity(process_count);
        for _ in 0..process_count {
            processors.push(Mutex::new(Self::spawn_worker(
                &binary_name,
                processor_name,
                spawn_path.as_ref(),
                config.compression,
            )?));
        }
        Ok(Self {
            config,
            binary_name,
            processor_name,
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
                    let path = P::path(&self.config)?;
                    *processor = Self::spawn_worker(
                        &self.binary_name,
                        self.processor_name,
                        &path,
                        self.config.compression,
                    )?;
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub fn for_processor<P: Processor>(
        config: &ConfigProcessors,
    ) -> Result<Arc<Self>, ProcessorError> {
        let key = (P::NAME, config.clone());
        let mut pools = POOLS
            .lock()
            .map_err(|_| ProcessorError::Protocol("processor pool mutex poisoned".to_string()))?;
        if let Some(pool) = pools.get(&key) {
            return Ok(Arc::clone(pool));
        }

        let binary_name = P::filename();
        let path = P::path(config)?;
        let pool = Arc::new(Self::new(config.clone(), binary_name, P::NAME, path)?);
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
            P::ID,
            request_id,
            payload,
            self.config.compression,
        )?;
        let frame = read_frame(&mut processor.stream)?;
        if frame.header.request_id != request_id {
            return Err(ProcessorError::UnexpectedResponse(format!(
                "request id mismatch, expected {}, got {}",
                request_id, frame.header.request_id
            )));
        }
        if frame.header.id != P::ID {
            return Err(ProcessorError::UnexpectedResponse(format!(
                "processor id mismatch, expected {}, got {}",
                P::ID,
                frame.header.id
            )));
        }

        match frame.header.kind {
            MessageKind::Response => Ok(postcard::from_bytes(&frame.payload)?),
            MessageKind::Error => {
                let failure: ProcessorFailure = postcard::from_bytes(&frame.payload)?;
                Err(ProcessorError::UnexpectedResponse(failure.message))
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
        spawn_path: &std::path::Path,
        compression: bool,
    ) -> Result<ProcessorHandle, ProcessorError> {
        let (socket_name, listener) = transport::bind_listener(binary_name)?;
        let mut child = Command::new(spawn_path)
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
        let mut stream = listener.accept()?;
        let frame = read_frame(&mut stream)?;
        if frame.header.kind != MessageKind::HelloAck {
            return Err(ProcessorError::UnexpectedResponse(
                "expected processor hello ack".to_string(),
            ));
        }
        let hello: Hello = postcard::from_bytes(&frame.payload)?;
        let _ = child.try_wait()?;
        Ok(ProcessorHandle {
            child,
            stream,
            pid: hello.pid,
        })
    }
}

fn is_retryable(error: &ProcessorError) -> bool {
    matches!(
        error,
        ProcessorError::Io(_)
            | ProcessorError::Protocol(_)
            | ProcessorError::Spawn(_)
            | ProcessorError::UnexpectedResponse(_)
    )
}

impl Drop for ProcessorHandle {
    fn drop(&mut self) {
        let _ = write_frame(&mut self.stream, MessageKind::Shutdown, 0, 0, &[], false);
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
