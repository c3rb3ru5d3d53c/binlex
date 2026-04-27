use super::super::support::{I386Fixture, I386Register, assert_amd64_semantics_match_unicorn, assert_complete_semantics};
use crate::Architecture;

fn vec128(bytes: [u8; 16]) -> u128 {
    u128::from_le_bytes(bytes)
}

#[test]
fn pextrd_semantics_stay_complete() {
    let cases = [
        ("pextrd eax, xmm0, 1", vec![0x66, 0x0f, 0x3a, 0x16, 0xc0, 0x01]),
        ("vpextrd eax, xmm0, 1", vec![0xc4, 0xe3, 0x79, 0x16, 0xc0, 0x01]),
    ];

    for (name, bytes) in cases {
        assert_complete_semantics(name, Architecture::AMD64, &bytes);
    }
}

#[test]
fn pextrd_semantics_match_unicorn_transitions() {
    let xmm0 = vec128([
        0x10, 0x80, 0x20, 0x70, 0x30, 0x60, 0x40, 0x50, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x11, 0x22,
    ]);

    assert_amd64_semantics_match_unicorn(
        "pextrd eax, xmm0, 1",
        &[0x66, 0x0f, 0x3a, 0x16, 0xc0, 0x01],
        I386Fixture {
            registers: vec![(I386Register::Eax, 0), (I386Register::Xmm0, xmm0)],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}
