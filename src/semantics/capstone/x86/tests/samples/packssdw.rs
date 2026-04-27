use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn packssdw_semantics_stay_complete() {
    let cases = [
        ("packssdw xmm0, xmm1", vec![0x66, 0x0f, 0x6b, 0xc1]),
        ("vpackssdw xmm0, xmm2, xmm1", vec![0xc5, 0xe9, 0x6b, 0xc1]),
    ];

    for (name, bytes) in cases {
        assert_complete_semantics(name, Architecture::AMD64, &bytes);
    }
}
