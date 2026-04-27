use super::super::support::{I386Fixture, I386Register, assert_amd64_semantics_match_unicorn, assert_complete_semantics};
use crate::Architecture;

#[test]
fn tzcnt_semantics_stay_complete() {
    assert_complete_semantics(
        "tzcnt ecx, eax",
        Architecture::AMD64,
        &[0xf3, 0x0f, 0xbc, 0xc8],
    );
}

#[test]
fn tzcnt_semantics_match_unicorn_transitions() {
    assert_amd64_semantics_match_unicorn(
        "tzcnt ecx, eax",
        &[0xf3, 0x0f, 0xbc, 0xc8],
        I386Fixture {
            registers: vec![(I386Register::Eax, 0x0000_0010), (I386Register::Ecx, 0)],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}
