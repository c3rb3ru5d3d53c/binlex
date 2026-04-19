use binlex::Config;

#[test]
fn test_config_serializes_flat_hash_paths() {
    let config = Config::default();
    let toml = config.to_string().expect("config should serialize");

    assert!(!config.blocks.tlsh.enabled);
    assert!(!config.functions.tlsh.enabled);
    assert!(!config.chromosomes.tlsh.enabled);
    assert!(toml.contains("[binlex.formats.file.sha256]"));
    assert!(toml.contains("[binlex.formats.file.tlsh]"));
    assert!(toml.contains("[binlex.blocks.sha256]"));
    assert!(toml.contains("[binlex.blocks.tlsh]"));
    assert!(toml.contains("[binlex.blocks.minhash]"));
    assert!(toml.contains("[binlex.instructions.semantics]"));
    assert!(toml.contains("[binlex.functions.sha256]"));
    assert!(toml.contains("[binlex.functions.tlsh]"));
    assert!(toml.contains("[binlex.functions.minhash]"));
    assert!(toml.contains("[binlex.chromosomes.sha256]"));
    assert!(toml.contains("[binlex.chromosomes.tlsh]"));
    assert!(toml.contains("[binlex.chromosomes.minhash]"));
    assert!(toml.contains("[binlex.chromosomes.mask]"));
    assert!(toml.contains("[binlex.chromosomes.masked]"));
    assert!(!toml.contains(".hashing."));
}
