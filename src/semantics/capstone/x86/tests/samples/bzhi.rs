use super::super::support::{I386Fixture, I386Register, assert_amd64_semantics_match_unicorn, assert_complete_semantics};
use crate::Architecture;

#[test]
fn bzhi_semantics_stay_complete() {
    assert_complete_semantics(
        "bzhi eax, ecx, edx",
        Architecture::AMD64,
        &[0xc4, 0xe2, 0x68, 0xf5, 0xc1],
    );
}

#[test]
fn bzhi_semantics_match_unicorn_transitions() {
    assert_amd64_semantics_match_unicorn(
        "bzhi eax, ecx, edx",
        &[0xc4, 0xe2, 0x68, 0xf5, 0xc1],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0),
                (I386Register::Ecx, 0xffff_ffff),
                (I386Register::Edx, 5),
            ],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}
