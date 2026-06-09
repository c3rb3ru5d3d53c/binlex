use binlex::Configuration;

#[test]
fn test_config_serializes_flat_hash_paths() {
    let config = Configuration::default();
    let toml = config.to_string().expect("config should serialize");

    assert!(toml.contains("[binlex.hashing.tlsh]"));
    assert!(toml.contains("[binlex.hashing.minhash]"));
    assert!(!toml.contains("[binlex.formats]"));
    assert!(!toml.contains("[binlex.imaging]"));
    assert!(!toml.contains("[binlex.blocks]"));
    assert!(!toml.contains("[binlex.chromosomes]"));
    assert!(!toml.contains("[binlex.formats.file.tlsh]"));
    assert!(!toml.contains("[binlex.blocks.tlsh]"));
    assert!(!toml.contains("[binlex.blocks.minhash]"));
    assert!(!toml.contains("[binlex.functions.tlsh]"));
    assert!(!toml.contains("[binlex.functions.minhash]"));
    assert!(!toml.contains("[binlex.chromosomes.tlsh]"));
    assert!(!toml.contains("[binlex.chromosomes.minhash]"));
    assert!(!toml.contains("[binlex.instructions]"));
    assert!(!toml.contains("[binlex.formats.file.sha256]"));
    assert!(!toml.contains("[binlex.blocks.sha256]"));
    assert!(!toml.contains("[binlex.functions.sha256]"));
    assert!(!toml.contains("[binlex.chromosomes.sha256]"));
    assert!(!toml.contains("[binlex.formats.file.entropy]"));
    assert!(!toml.contains("[binlex.blocks.entropy]"));
    assert!(!toml.contains("[binlex.functions.entropy]"));
    assert!(!toml.contains("[binlex.chromosomes.mask]"));
    assert!(!toml.contains("[binlex.chromosomes.masked]"));
}
