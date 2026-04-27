use super::super::support::{I386Fixture, I386Register, assert_amd64_semantics_match_unicorn, assert_complete_semantics};
use crate::Architecture;

fn vec128(bytes: [u8; 16]) -> u128 {
    u128::from_le_bytes(bytes)
}

#[test]
fn pmovsxbw_semantics_stay_complete() {
    assert_complete_semantics(
        "pmovsxbw xmm0, xmm1",
        Architecture::AMD64,
        &[0x66, 0x0f, 0x38, 0x20, 0xc1],
    );
}

#[test]
fn pmovsxbw_semantics_match_unicorn_transitions() {
    let xmm1 = vec128([
        0x01, 0xff, 0x02, 0xfe, 0x03, 0xfd, 0x04, 0xfc, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
        0x99, 0x88,
    ]);

    assert_amd64_semantics_match_unicorn(
        "pmovsxbw xmm0, xmm1",
        &[0x66, 0x0f, 0x38, 0x20, 0xc1],
        I386Fixture {
            registers: vec![(I386Register::Xmm0, 0), (I386Register::Xmm1, xmm1)],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}
