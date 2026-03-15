use std::collections::HashMap;

use interprocess::local_socket::Stream;

use crate::processing::error::ProcessorError;
use crate::processing::protocol::{
    Hello, HelloProcessor, MessageKind, ProcessorFailure, read_frame, write_frame,
};
use crate::processors::{RegisteredProcessorDispatch, processor_registration_by_name};

pub fn run_child_loop(
    mut stream: Stream,
    backend_name: &str,
    processor_name: &str,
    processors: Vec<RegisteredProcessorDispatch>,
    compression_enabled: bool,
) -> Result<(), ProcessorError> {
    let processor_map = processors
        .into_iter()
        .map(|processor| (processor.id, processor.dispatch))
        .collect::<HashMap<_, _>>();

    let hello = Hello {
        protocol_version: crate::processing::protocol::VERSION,
        backend_name: backend_name.to_string(),
        host_os: crate::processors::ProcessorOs::current(),
        processor_name: processor_name.to_string(),
        supported_ids: processor_map.keys().copied().collect(),
        processors: processor_map
            .keys()
            .filter_map(|id| {
                processor_registration_by_name(processor_name).and_then(|registration| {
                    (registration.id == *id).then(|| HelloProcessor {
                        id: *id,
                        name: registration.name().to_string(),
                        os: registration.registration.os.to_vec(),
                    })
                })
            })
            .collect(),
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
                let response = match processor_map.get(&frame.header.id) {
                    Some(processor) => processor.process(&frame.payload),
                    None => Err(ProcessorError::Protocol(format!(
                        "unsupported processor id {}",
                        frame.header.id
                    ))),
                };

                match response {
                    Ok(payload) => write_frame(
                        &mut stream,
                        MessageKind::Response,
                        frame.header.id,
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
                            frame.header.id,
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
