use super::super::support::{I386Fixture, I386Register, assert_amd64_semantics_match_unicorn, assert_complete_semantics};
use crate::Architecture;

#[test]
fn movntdq_semantics_stay_complete() {
    let cases = [
        (
            "movntdq xmmword ptr [rax], xmm0",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0xe7, 0x00],
        ),
        (
            "vmovntdq xmmword ptr [rax], xmm0",
            Architecture::AMD64,
            vec![0xc5, 0xf9, 0xe7, 0x00],
        ),
    ];

    for (name, architecture, bytes) in cases {
        assert_complete_semantics(name, architecture, &bytes);
    }
}

#[test]
fn movntdq_semantics_match_unicorn_transitions() {
    let xmm0 = u128::from_le_bytes([
        0x10, 0x80, 0x20, 0x70, 0x30, 0x60, 0x40, 0x50, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x11, 0x22,
    ]);

    assert_amd64_semantics_match_unicorn(
        "movntdq xmmword ptr [rax], xmm0",
        &[0x66, 0x0f, 0xe7, 0x00],
        I386Fixture {
            registers: vec![(I386Register::Rax, 0x3000), (I386Register::Xmm0, xmm0)],
            eflags: 1 << 1,
            memory: vec![(0x3000, vec![0; 16])],
        },
    );
}
