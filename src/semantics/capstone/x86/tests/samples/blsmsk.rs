use super::super::support::{I386Fixture, I386Register, assert_amd64_semantics_match_unicorn, assert_complete_semantics};
use crate::Architecture;

#[test]
fn blsmsk_semantics_stay_complete() {
    assert_complete_semantics(
        "blsmsk eax, ecx",
        Architecture::AMD64,
        &[0xc4, 0xe2, 0x78, 0xf3, 0xd1],
    );
}

#[test]
fn blsmsk_semantics_match_unicorn_transitions() {
    assert_amd64_semantics_match_unicorn(
        "blsmsk eax, ecx",
        &[0xc4, 0xe2, 0x78, 0xf3, 0xd1],
        I386Fixture {
            registers: vec![(I386Register::Eax, 0), (I386Register::Ecx, 0b1011000)],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}
