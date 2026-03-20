use binlex::Config;
use binlex::formats::file::File;
use binlex::genetics::Chromosome;
use binlex::imaging::{PNG, Palette, SVG, Terminal};

#[test]
fn file_direct_accessors_ignore_serialization_flags() {
    let mut config = Config::default();
    config.formats.file.hashing.sha256.enabled = false;
    config.formats.file.hashing.tlsh.enabled = false;
    config.formats.file.entropy.enabled = false;

    let file = File::from_bytes(
        vec![
            0x3A, 0x7F, 0x92, 0x5C, 0xE4, 0xA1, 0xD8, 0x47, 0x29, 0xB3, 0x1E, 0x8D, 0x4F, 0x6A,
            0xCD, 0x72, 0x90, 0x33, 0xB6, 0xF1, 0xD4, 0x5E, 0xAA, 0x64, 0x13, 0xFA, 0x38, 0x9C,
            0x41, 0xB8, 0xD0, 0xE7, 0x6F, 0x25, 0xA9, 0x54, 0x1B, 0xC2, 0x8E, 0xF5, 0x77, 0x3D,
            0xAC, 0x12, 0x8A, 0x9E, 0x6B, 0xC7, 0x5A, 0xEF,
        ],
        config,
    );

    assert!(file.sha256().is_some());
    assert!(file.tlsh().is_some());
    assert!(file.entropy().is_some());

    let value: serde_json::Value =
        serde_json::from_str(&file.json().expect("file json should serialize"))
            .expect("file json should parse");
    assert!(value.get("sha256").is_none());
    assert!(value.get("tlsh").is_none());
    assert!(value.get("entropy").is_none());
}

#[test]
fn chromosome_direct_accessors_ignore_serialization_flags() {
    let mut config = Config::default();
    config.chromosomes.features.enabled = false;
    config.chromosomes.hashing.sha256.enabled = false;
    config.chromosomes.hashing.tlsh.enabled = false;
    config.chromosomes.hashing.minhash.enabled = false;
    config.chromosomes.entropy.enabled = false;

    let chromosome = Chromosome::new(
        "3a7f925ce4a1d84729b31e8d4f6acd729033b6f1d45eaa6413fa389c41b8d0e76f25a9541bc28ef5773dac128a9e6bc75aef".to_string(),
        config,
    )
    .expect("chromosome should parse");

    assert!(!chromosome.feature().is_empty());
    assert!(chromosome.sha256().is_some());
    assert!(chromosome.tlsh().is_some());
    assert!(chromosome.minhash().is_some());
    assert!(chromosome.entropy().is_some());

    let value: serde_json::Value =
        serde_json::from_str(&chromosome.json().expect("chromosome json should serialize"))
            .expect("chromosome json should parse");
    assert!(value.get("feature").is_none());
    assert!(value.get("sha256").is_none());
    assert!(value.get("tlsh").is_none());
    assert!(value.get("minhash").is_none());
    assert!(value.get("entropy").is_none());
}

#[test]
fn imaging_direct_accessors_ignore_config_flags() {
    let mut config = Config::default();
    config.disable_imaging_hashing();

    let data = [0x00, 0x22, 0x44, 0x88, 0xaa, 0xcc, 0xee, 0xff];
    let png = PNG::with_options(&data, Palette::Grayscale, 2, 4, config.clone());
    let svg = SVG::with_options(&data, Palette::Grayscale, 2, 4, config.clone());
    let terminal = Terminal::with_options(&data, Palette::Grayscale, 2, 4, config);

    assert!(png.sha256().is_some());
    assert!(png.tlsh().is_some());
    assert!(png.minhash().is_some());
    assert!(png.ahash().is_some());
    assert!(png.dhash().is_some());
    assert!(png.phash().is_some());

    assert_eq!(png.sha256(), svg.sha256());
    assert_eq!(png.sha256(), terminal.sha256());
    assert_eq!(png.tlsh(), svg.tlsh());
    assert_eq!(png.tlsh(), terminal.tlsh());
    assert_eq!(png.minhash(), svg.minhash());
    assert_eq!(png.minhash(), terminal.minhash());
    assert_eq!(png.ahash(), svg.ahash());
    assert_eq!(png.ahash(), terminal.ahash());
    assert_eq!(png.dhash(), svg.dhash());
    assert_eq!(png.dhash(), terminal.dhash());
    assert_eq!(png.phash(), svg.phash());
    assert_eq!(png.phash(), terminal.phash());
}
