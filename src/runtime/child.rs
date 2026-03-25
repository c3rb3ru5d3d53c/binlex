use interprocess::local_socket::Stream;

use crate::processor::ProcessorRegistration;
use crate::runtime::error::ProcessorError;
use crate::runtime::transports::ipc::local;
use crate::runtime::transports::ipc::protocol::{
    Hello, HelloProcessor, MessageKind, ProcessorFailure, read_frame, write_frame,
};
use crate::runtime::{JsonProcessorRequest, Processor};

#[derive(Debug)]
pub enum ProcessorEntryError {
    Connect(ProcessorError),
    Runtime(ProcessorError),
}

impl std::fmt::Display for ProcessorEntryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect(error) => write!(f, "{}", error),
            Self::Runtime(error) => write!(f, "{}", error),
        }
    }
}

impl std::error::Error for ProcessorEntryError {}

pub fn describe_processor(registration: &ProcessorRegistration) -> Result<(), ProcessorEntryError> {
    serde_json::to_writer(std::io::stdout(), registration).map_err(|error| {
        ProcessorEntryError::Runtime(ProcessorError::Serialization(error.to_string()))
    })
}

pub fn run_external_processor_entry<P>(
    registration: &ProcessorRegistration,
    socket_name: &str,
    compression_enabled: bool,
) -> Result<(), ProcessorEntryError>
where
    P: crate::processor::JsonProcessor + Processor + Default,
{
    let stream = local::connect(socket_name).map_err(ProcessorEntryError::Connect)?;
    run_child_loop::<P>(stream, registration, compression_enabled)
        .map_err(ProcessorEntryError::Runtime)
}

pub fn run_child_loop<P>(
    mut stream: Stream,
    registration: &ProcessorRegistration,
    compression_enabled: bool,
) -> Result<(), ProcessorError>
where
    P: crate::processor::JsonProcessor + Processor + Default,
{
    let hello = Hello {
        protocol_version: crate::runtime::transports::ipc::protocol::VERSION,
        backend_name: registration.backend_name.clone(),
        binlex_version: crate::VERSION.to_string(),
        host_os: crate::processor::ProcessorOs::current(),
        processor_name: registration.name.clone(),
        supported_ids: vec![1],
        processors: vec![HelloProcessor {
            id: 1,
            name: registration.name.clone(),
            requires: registration.requires.clone(),
            os: registration.operating_systems.clone(),
        }],
        pid: std::process::id(),
    };
    let hello_payload = postcard::to_allocvec(&hello)?;
    write_frame(
        &mut stream,
        MessageKind::HelloAck,
        0,
        0,
        &hello_payload,
        compression_enabled,
    )?;

    loop {
        let frame = match read_frame(&mut stream) {
            Ok(frame) => frame,
            Err(ProcessorError::Io(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(());
            }
            Err(error) => return Err(error),
        };

        match frame.header.kind {
            MessageKind::Request => {
                let response = postcard::from_bytes::<JsonProcessorRequest>(&frame.payload)
                    .map_err(ProcessorError::from)
                    .and_then(crate::runtime::execute::execute_external::<P>)
                    .and_then(|response| {
                        postcard::to_allocvec(&response).map_err(ProcessorError::from)
                    });

                match response {
                    Ok(payload) => write_frame(
                        &mut stream,
                        MessageKind::Response,
                        1,
                        frame.header.request_id,
                        &payload,
                        compression_enabled,
                    )?,
                    Err(error) => {
                        let payload = postcard::to_allocvec(&ProcessorFailure {
                            message: error.to_string(),
                        })?;
                        write_frame(
                            &mut stream,
                            MessageKind::Error,
                            1,
                            frame.header.request_id,
                            &payload,
                            compression_enabled,
                        )?;
                    }
                }
            }
            MessageKind::Shutdown => {
                write_frame(
                    &mut stream,
                    MessageKind::ShutdownAck,
                    0,
                    frame.header.request_id,
                    &[],
                    compression_enabled,
                )?;
                return Ok(());
            }
            _ => {
                return Err(ProcessorError::Protocol(format!(
                    "unexpected message kind in child: {:?}",
                    frame.header.kind
                )));
            }
        }
    }
}

pub fn handle_describe_or_run<P>(
    registration: &ProcessorRegistration,
    args: impl IntoIterator<Item = String>,
) -> Result<(), ProcessorEntryError>
where
    P: crate::processor::JsonProcessor + Processor + Default,
{
    let mut socket_name: Option<String> = None;
    let mut compression_enabled = false;
    let mut describe = false;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--describe" => describe = true,
            "--socket" => socket_name = args.next(),
            "--compression" => {
                compression_enabled = args.next().as_deref() == Some("true");
            }
            "--processor" => {
                let _ = args.next();
            }
            _ => {}
        }
    }

    if describe {
        return describe_processor(registration);
    }

    let socket_name = socket_name.ok_or_else(|| {
        ProcessorEntryError::Runtime(ProcessorError::Protocol(format!(
            "missing socket for processor {}",
            registration.name
        )))
    })?;
    run_external_processor_entry::<P>(registration, &socket_name, compression_enabled)
}
