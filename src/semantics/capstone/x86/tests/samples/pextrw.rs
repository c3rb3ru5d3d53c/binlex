use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn pextrw_semantics_stay_complete() {
    let cases = [
        ("vpextrw eax, xmm0, 1", vec![0xc5, 0xf9, 0xc5, 0xc0, 0x01]),
        ("pextrw eax, xmm0, 1", vec![0x66, 0x0f, 0xc5, 0xc0, 0x01]),
    ];

    for (name, bytes) in cases {
        assert_complete_semantics(name, Architecture::AMD64, &bytes);
    }
}
