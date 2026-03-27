fn main() {
    if let Err(error) = binlex::runtime::child::handle_describe_or_run::<
        binlex_processor_complete_test::CompleteTestProcessor,
    >(
        &binlex_processor_complete_test::registration(),
        std::env::args().skip(1),
    ) {
        match error {
            binlex::runtime::child::ProcessorEntryError::Connect(_) => std::process::exit(3),
            binlex::runtime::child::ProcessorEntryError::Runtime(_) => std::process::exit(4),
        }
    }
}
