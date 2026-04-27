use super::super::support::{I386Fixture, I386Register, assert_amd64_semantics_match_unicorn, assert_complete_semantics};
use crate::Architecture;

fn vec128(bytes: [u8; 16]) -> u128 {
    u128::from_le_bytes(bytes)
}

#[test]
fn pshufb_semantics_stay_complete() {
    assert_complete_semantics(
        "pshufb xmm0, xmm1",
        Architecture::AMD64,
        &[0x66, 0x0f, 0x38, 0x00, 0xc1],
    );
}

#[test]
fn pshufb_semantics_match_unicorn_transitions() {
    let xmm0 = vec128([
        0x10, 0x80, 0x20, 0x70, 0x30, 0x60, 0x40, 0x50, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x11, 0x22,
    ]);
    let mask = vec128([
        0x00, 0x81, 0x02, 0x83, 0x04, 0x85, 0x06, 0x87, 0x08, 0x89, 0x0a, 0x8b, 0x0c, 0x8d,
        0x0e, 0x8f,
    ]);

    assert_amd64_semantics_match_unicorn(
        "pshufb xmm0, xmm1",
        &[0x66, 0x0f, 0x38, 0x00, 0xc1],
        I386Fixture {
            registers: vec![(I386Register::Xmm0, xmm0), (I386Register::Xmm1, mask)],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}
