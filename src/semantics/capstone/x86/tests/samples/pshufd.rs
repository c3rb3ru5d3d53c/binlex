use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn pshufd_semantics_stay_complete() {
    let cases = [
        ("pshufd xmm0, xmm1, 0x1b", vec![0x66, 0x0f, 0x70, 0xc1, 0x1b]),
        ("vpshufd xmm0, xmm1, 0x1b", vec![0xc5, 0xf9, 0x70, 0xc1, 0x1b]),
    ];

    for (name, bytes) in cases {
        assert_complete_semantics(name, Architecture::AMD64, &bytes);
    }
}
