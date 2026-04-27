use super::super::support::{I386Fixture, I386Register, assert_complete_semantics, assert_i386_semantics_match_unicorn};
use crate::Architecture;

#[test]
fn bsr_semantics_stay_complete() {
    assert_complete_semantics("bsr ecx, eax", Architecture::I386, &[0x0f, 0xbd, 0xc8]);
}

#[test]
fn bsr_semantics_match_unicorn_transitions() {
    assert_i386_semantics_match_unicorn(
        "bsr ecx, eax",
        &[0x0f, 0xbd, 0xc8],
        I386Fixture {
            registers: vec![(I386Register::Eax, 0x0000_0010), (I386Register::Ecx, 0)],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}
