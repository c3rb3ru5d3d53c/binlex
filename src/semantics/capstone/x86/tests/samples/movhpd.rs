use super::super::support::{I386Fixture, I386Register, assert_amd64_semantics_match_unicorn, assert_complete_semantics};
use crate::Architecture;

fn vec128(bytes: [u8; 16]) -> u128 {
    u128::from_le_bytes(bytes)
}

#[test]
fn movhpd_semantics_stay_complete() {
    assert_complete_semantics(
        "movhpd xmm0, qword ptr [rax]",
        Architecture::AMD64,
        &[0x66, 0x0f, 0x16, 0x00],
    );
}

#[test]
fn movhpd_semantics_match_unicorn_transitions() {
    let xmm0 = vec128([
        0x10, 0x80, 0x20, 0x70, 0x30, 0x60, 0x40, 0x50, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x11, 0x22,
    ]);
    let mem128 = [
        0xde, 0xad, 0xbe, 0xef, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x13, 0x57,
        0x9b, 0xdf,
    ];

    assert_amd64_semantics_match_unicorn(
        "movhpd xmm0, qword ptr [rax]",
        &[0x66, 0x0f, 0x16, 0x00],
        I386Fixture {
            registers: vec![(I386Register::Rax, 0x3000), (I386Register::Xmm0, xmm0)],
            eflags: 1 << 1,
            memory: vec![(0x3000, mem128[..8].to_vec())],
        },
    );
}
