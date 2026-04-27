use super::super::support::{
    I386Fixture, I386Register, assert_complete_semantics,
    assert_i386_instruction_roundtrip_match_unicorn, assert_i386_semantics_match_unicorn,
};
use crate::Architecture;

#[test]
fn adc_semantics_stay_complete() {
    assert_complete_semantics("adc eax, ebx", Architecture::I386, &[0x11, 0xd8]);
}

#[test]
fn adc_semantics_match_unicorn_transitions() {
    assert_i386_semantics_match_unicorn(
        "adc eax, ebx",
        &[0x11, 0xd8],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0xffff_ffff),
                (I386Register::Ebx, 0x0000_0000),
            ],
            eflags: (1 << 1) | (1 << 0),
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_adc_eax_ebx_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "adc eax, ebx",
        &[0x11, 0xd8],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1122_3344),
                (I386Register::Ebx, 0x0102_0304),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 0x203,
            memory: vec![],
        },
    );
}
