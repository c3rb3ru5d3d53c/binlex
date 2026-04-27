use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn pextrq_semantics_stay_complete() {
    let cases = [
        ("vpextrq rax, xmm0, 1", vec![0xc4, 0xe3, 0xf9, 0x16, 0xc0, 0x01]),
        (
            "pextrq rax, xmm0, 1",
            vec![0x66, 0x48, 0x0f, 0x3a, 0x16, 0xc0, 0x01],
        ),
    ];

    for (name, bytes) in cases {
        assert_complete_semantics(name, Architecture::AMD64, &bytes);
    }
}
