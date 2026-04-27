use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn punpckhwd_semantics_stay_complete() {
    let cases = [
        (
            "punpckhwd xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x69, 0xc1],
        ),
        (
            "vpunpckhwd xmm0, xmm2, xmm1",
            Architecture::AMD64,
            vec![0xc5, 0xe9, 0x69, 0xc1],
        ),
    ];

    for (name, architecture, bytes) in cases {
        assert_complete_semantics(name, architecture, &bytes);
    }
}
