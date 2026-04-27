use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn movss_semantics_stay_complete() {
    let cases = [
        (
            "movss xmm0, xmm1",
            Architecture::AMD64,
            vec![0xf3, 0x0f, 0x10, 0xc1],
        ),
        (
            "movss xmm0, dword ptr [rax]",
            Architecture::AMD64,
            vec![0xf3, 0x0f, 0x10, 0x00],
        ),
    ];

    for (name, architecture, bytes) in cases {
        assert_complete_semantics(name, architecture, &bytes);
    }
}
