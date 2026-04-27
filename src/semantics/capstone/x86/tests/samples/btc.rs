use super::super::support::{I386Fixture, I386Register, assert_complete_semantics, assert_i386_semantics_match_unicorn};
use crate::Architecture;

#[test]
fn btc_semantics_stay_complete() {
    assert_complete_semantics(
        "btc eax, 1",
        Architecture::I386,
        &[0x0f, 0xba, 0xf8, 0x01],
    );
}

#[test]
fn btc_semantics_match_unicorn_transitions() {
    assert_i386_semantics_match_unicorn(
        "btc eax, 1",
        &[0x0f, 0xba, 0xf8, 0x01],
        I386Fixture {
            registers: vec![(I386Register::Eax, 0b10)],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}
