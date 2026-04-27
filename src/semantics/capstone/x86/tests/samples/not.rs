use super::super::support::{
    I386Fixture, I386Register, assert_complete_semantics,
    assert_i386_instruction_roundtrip_match_unicorn, assert_i386_semantics_match_unicorn,
};
use crate::Architecture;

#[test]
fn not_semantics_stay_complete() {
    assert_complete_semantics("not eax", Architecture::I386, &[0xf7, 0xd0]);
}

#[test]
fn not_semantics_match_unicorn_transitions() {
    assert_i386_semantics_match_unicorn(
        "not eax",
        &[0xf7, 0xd0],
        I386Fixture {
            registers: vec![(I386Register::Eax, 0x1234_5678)],
            eflags: (1 << 1) | (1 << 6),
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_not_eax_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "not eax",
        &[0xf7, 0xd0],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1122_3344),
                (I386Register::Ebx, 0x3000),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 0x247,
            memory: vec![],
        },
    );
}
