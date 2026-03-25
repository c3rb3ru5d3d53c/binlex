fn main() {
    if let Err(error) = binlex::runtime::child::handle_describe_or_run::<
        binlex_processor_embeddings::EmbeddingsProcessor,
    >(
        &binlex_processor_embeddings::registration(),
        std::env::args().skip(1),
    ) {
        match error {
            binlex::runtime::child::ProcessorEntryError::Connect(_) => std::process::exit(3),
            binlex::runtime::child::ProcessorEntryError::Runtime(_) => std::process::exit(4),
        }
    }
}
