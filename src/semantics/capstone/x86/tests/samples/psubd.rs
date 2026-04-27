use super::super::support::{
    I386Fixture, I386Register, assert_complete_semantics,
    assert_i386_instruction_roundtrip_match_unicorn,
};
use crate::Architecture;

#[test]
fn psubd_semantics_stay_complete() {
    assert_complete_semantics(
        "psubd xmm0, xmm1",
        Architecture::AMD64,
        &[0x66, 0x0f, 0xfa, 0xc1],
    );
}

#[test]
fn i386_roundtrip_psubd_xmm0_xmm1_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "psubd xmm0, xmm1",
        &[0x66, 0x0f, 0xfa, 0xc1],
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
                (
                    I386Register::Xmm0,
                    0x0102_0304_2223_2425_8000_0001_0000_0005,
                ),
                (
                    I386Register::Xmm1,
                    0x0001_0002_1112_1314_0000_0001_0000_0003,
                ),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}
