use super::super::support::{I386Fixture, I386Register, assert_amd64_semantics_match_unicorn, assert_complete_semantics};
use crate::Architecture;

#[test]
fn pdep_semantics_stay_complete() {
    assert_complete_semantics(
        "pdep eax, ebx, ecx",
        Architecture::AMD64,
        &[0xc4, 0xe2, 0x63, 0xf5, 0xc1],
    );
}

#[test]
fn pdep_semantics_match_unicorn_transitions() {
    assert_amd64_semantics_match_unicorn(
        "pdep eax, ebx, ecx",
        &[0xc4, 0xe2, 0x63, 0xf5, 0xc1],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0),
                (I386Register::Ebx, 0b1011),
                (I386Register::Ecx, 0b0011_0101),
            ],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}
