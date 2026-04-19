use binlex::formats::MACHO;
use binlex::{Architecture, Config};

#[test]
fn arm64_macho_sample_entrypoint_maps_into_executable_range() {
    let macho = MACHO::new("samples/sample.macho".to_string(), Config::new()).expect("macho");
    let slice = macho
        .slices()
        .find(|slice| slice.architecture() == Architecture::ARM64)
        .expect("arm64 slice");

    let entrypoint = slice
        .entrypoint_virtual_address()
        .expect("mapped entrypoint");
    let ranges = slice.executable_virtual_address_ranges();

    assert_eq!(entrypoint, 0x100003948);
    assert!(
        ranges
            .iter()
            .any(|(start, end)| entrypoint >= *start && entrypoint < *end),
        "arm64 macho entrypoint should lie within an executable range"
    );
}
