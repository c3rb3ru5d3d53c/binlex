use super::super::support::{
    I386Fixture, I386Register, assert_complete_semantics,
    assert_i386_instruction_roundtrip_match_unicorn,
};
use crate::Architecture;

#[test]
fn pslld_semantics_stay_complete() {
    assert_complete_semantics(
        "pslld xmm0, 1",
        Architecture::AMD64,
        &[0x66, 0x0f, 0x72, 0xf0, 0x01],
    );
}

#[test]
fn i386_roundtrip_pslld_xmm0_4_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "pslld xmm0, 4",
        &[0x66, 0x0f, 0x72, 0xf0, 0x04],
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
                    0x1234_5678_89ab_cdef_0fed_cba9_7654_3210,
                ),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}
