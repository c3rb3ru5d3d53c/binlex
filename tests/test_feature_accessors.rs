use binlex::Config;
use binlex::formats::file::File;
use binlex::genetics::Chromosome;
use binlex::imaging::{PNG, Palette, SVG, Terminal};

#[test]
fn file_direct_accessors_ignore_serialization_flags() {
    let mut config = Config::default();
    config.formats.file.sha256.enabled = false;
    config.formats.file.tlsh.enabled = false;
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
    config.chromosomes.vector.enabled = false;
    config.chromosomes.sha256.enabled = false;
    config.chromosomes.tlsh.enabled = false;
    config.chromosomes.minhash.enabled = false;
    config.chromosomes.entropy.enabled = false;

    let chromosome = Chromosome::from_pattern(
        "3a7f925ce4a1d84729b31e8d4f6acd729033b6f1d45eaa6413fa389c41b8d0e76f25a9541bc28ef5773dac128a9e6bc75aef".to_string(),
        config,
    )
    .expect("chromosome should parse");

    assert!(!chromosome.vector().is_empty());
    assert!(chromosome.sha256().is_some());
    assert!(chromosome.tlsh().is_some());
    assert!(chromosome.minhash().is_some());
    assert!(chromosome.entropy().is_some());

    let png = chromosome.png();
    let svg = chromosome.svg();
    assert!(png.phash().is_some());
    assert!(png.ahash().is_some());
    assert!(png.dhash().is_some());
    assert_eq!(
        png.phash().and_then(|hash| hash.hexdigest()),
        svg.phash().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.ahash().and_then(|hash| hash.hexdigest()),
        svg.ahash().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.dhash().and_then(|hash| hash.hexdigest()),
        svg.dhash().and_then(|hash| hash.hexdigest())
    );

    let value: serde_json::Value =
        serde_json::from_str(&chromosome.json().expect("chromosome json should serialize"))
            .expect("chromosome json should parse");
    assert!(value.get("vector").is_none());
    assert!(value.get("sha256").is_none());
    assert!(value.get("tlsh").is_none());
    assert!(value.get("minhash").is_none());
    assert!(value.get("entropy").is_none());
}

#[test]
fn chromosome_bytes_zero_masked_bits_without_compaction() {
    let config = Config::default();
    let chromosome = Chromosome::new(vec![0xAF, 0x12], vec![0x03, 0xF0], config)
        .expect("chromosome should build");

    assert_eq!(chromosome.bytes(), vec![0xAF, 0x12]);
    assert_eq!(chromosome.mask(), vec![0x03, 0xF0]);
    assert_eq!(chromosome.masked(), vec![0xAC, 0x02]);
    assert_eq!(chromosome.vector(), vec![0xA, 0xC, 0x0, 0x2]);
    assert_eq!(chromosome.pattern(), "a??2");
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

    assert_eq!(
        png.sha256().and_then(|hash| hash.hexdigest()),
        svg.sha256().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.sha256().and_then(|hash| hash.hexdigest()),
        terminal.sha256().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.tlsh().and_then(|hash| hash.hexdigest()),
        svg.tlsh().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.tlsh().and_then(|hash| hash.hexdigest()),
        terminal.tlsh().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.minhash().and_then(|hash| hash.hexdigest()),
        svg.minhash().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.minhash().and_then(|hash| hash.hexdigest()),
        terminal.minhash().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.ahash().and_then(|hash| hash.hexdigest()),
        svg.ahash().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.ahash().and_then(|hash| hash.hexdigest()),
        terminal.ahash().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.dhash().and_then(|hash| hash.hexdigest()),
        svg.dhash().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.dhash().and_then(|hash| hash.hexdigest()),
        terminal.dhash().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.phash().and_then(|hash| hash.hexdigest()),
        svg.phash().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.phash().and_then(|hash| hash.hexdigest()),
        terminal.phash().and_then(|hash| hash.hexdigest())
    );
}
