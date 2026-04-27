use super::super::support::{I386Fixture, I386Register, assert_amd64_semantics_match_unicorn, assert_complete_semantics};
use crate::Architecture;

#[test]
fn psllq_semantics_stay_complete() {
    assert_complete_semantics(
        "psllq xmm0, 1",
        Architecture::AMD64,
        &[0x66, 0x0f, 0x73, 0xf0, 0x01],
    );
}

#[test]
fn psllq_semantics_match_unicorn_transitions() {
    let xmm0 = u128::from_le_bytes([
        0x10, 0x80, 0x20, 0x70, 0x30, 0x60, 0x40, 0x50, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x11, 0x22,
    ]);

    assert_amd64_semantics_match_unicorn(
        "psllq xmm0, 1",
        &[0x66, 0x0f, 0x73, 0xf0, 0x01],
        I386Fixture {
            registers: vec![(I386Register::Xmm0, xmm0)],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}
