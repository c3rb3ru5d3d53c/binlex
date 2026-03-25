use binlex::Config;

#[test]
fn test_config_serializes_flat_hash_paths() {
    let config = Config::default();
    let toml = config.to_string().expect("config should serialize");

    assert!(toml.contains("[formats.file.sha256]"));
    assert!(toml.contains("[formats.file.tlsh]"));
    assert!(toml.contains("[blocks.sha256]"));
    assert!(toml.contains("[blocks.tlsh]"));
    assert!(toml.contains("[blocks.minhash]"));
    assert!(toml.contains("[functions.sha256]"));
    assert!(toml.contains("[functions.tlsh]"));
    assert!(toml.contains("[functions.minhash]"));
    assert!(toml.contains("[chromosomes.sha256]"));
    assert!(toml.contains("[chromosomes.tlsh]"));
    assert!(toml.contains("[chromosomes.minhash]"));
    assert!(toml.contains("[processors.embeddings.transport.ipc]"));
    assert!(toml.contains("[processors.embeddings.transport.http]"));
    assert!(!toml.contains(".hashing."));
}
