#[cfg(not(target_os = "windows"))]
fn main() {
    use std::env;
    use std::process;

    use binlex::processor::dispatch_by_name;
    use binlex::runtime::child::run_child_loop;
    use binlex::runtime::modes::ipc::local;

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
        Some(processor_name) => processor_name,
        None => process::exit(2),
    };
    let socket_name = match socket_name {
        Some(socket_name) => socket_name,
        None => process::exit(2),
    };

    let stream = match local::connect(&socket_name) {
        Ok(stream) => stream,
        Err(_) => process::exit(3),
    };

    let processor = match dispatch_by_name(&processor_name) {
        Some(processor) => processor,
        None => process::exit(2),
    };

    if run_child_loop(
        stream,
        "binlex-processor",
        &processor_name,
        vec![processor],
        compression_enabled,
    )
    .is_err()
    {
        process::exit(4);
    }
}

#[cfg(target_os = "windows")]
fn main() {
    std::process::exit(1);
}
