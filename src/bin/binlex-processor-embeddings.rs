fn main() {
    use std::env;
    use std::process;

    let mut processor_name: Option<String> = None;
    let mut socket_name: Option<String> = None;
    let mut compression_enabled = false;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--processor" => processor_name = args.next(),
            "--socket" => socket_name = args.next(),
            "--compression" => {
                compression_enabled = args.next().as_deref() == Some("true");
            }
            _ => {}
        }
    }

    let processor_name = match processor_name {
        Some(processor_name) if processor_name == "embeddings" => processor_name,
        _ => process::exit(2),
    };
    let socket_name = match socket_name {
        Some(socket_name) => socket_name,
        None => process::exit(2),
    };

    match binlex::runtime::child::run_processor_entry(
        "binlex-processor-embeddings",
        &processor_name,
        &socket_name,
        compression_enabled,
    ) {
        Ok(()) => {}
        Err(binlex::runtime::child::ProcessorEntryError::InvalidProcessor(_)) => process::exit(2),
        Err(binlex::runtime::child::ProcessorEntryError::Connect(_)) => process::exit(3),
        Err(binlex::runtime::child::ProcessorEntryError::Runtime(_)) => process::exit(4),
    }
}
