use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn pextrb_semantics_stay_complete() {
    let cases = [
        ("pextrb eax, xmm0, 1", vec![0x66, 0x0f, 0x3a, 0x14, 0xc0, 0x01]),
        ("vpextrb eax, xmm0, 1", vec![0xc4, 0xe3, 0x79, 0x14, 0xc0, 0x01]),
    ];

    for (name, bytes) in cases {
        assert_complete_semantics(name, Architecture::AMD64, &bytes);
    }
}
