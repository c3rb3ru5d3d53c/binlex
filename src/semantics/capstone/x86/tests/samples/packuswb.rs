use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn packuswb_semantics_stay_complete() {
    let cases = [
        ("packuswb xmm0, xmm1", vec![0x66, 0x0f, 0x67, 0xc1]),
        ("vpackuswb xmm0, xmm2, xmm1", vec![0xc5, 0xe9, 0x67, 0xc1]),
    ];

    for (name, bytes) in cases {
        assert_complete_semantics(name, Architecture::AMD64, &bytes);
    }
}
