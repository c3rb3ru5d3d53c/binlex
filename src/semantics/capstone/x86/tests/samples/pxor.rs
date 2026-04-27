use super::super::support::{
    I386Fixture, I386Register, assert_amd64_instruction_roundtrip_match_unicorn,
    assert_complete_semantics, assert_i386_instruction_roundtrip_match_unicorn,
};
use crate::Architecture;

#[test]
fn pxor_semantics_stay_complete() {
    assert_complete_semantics(
        "pxor xmm0, xmm1",
        Architecture::AMD64,
        &[0x66, 0x0f, 0xef, 0xc1],
    );
}

#[test]
fn i386_roundtrip_pxor_xmm0_xmm0_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "pxor xmm0, xmm0",
        &[0x66, 0x0f, 0xef, 0xc0],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1122_3344),
                (I386Register::Ebx, 0x5566_7788),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
                (
                    I386Register::Xmm0,
                    0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00,
                ),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_pxor_xmm0_xmm1_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "pxor xmm0, xmm1",
        &[0x66, 0x0f, 0xef, 0xc1],
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
                    0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00,
                ),
                (
                    I386Register::Xmm1,
                    0xff00_ee11_dd22_cc33_bb44_aa55_9966_8877,
                ),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn amd64_roundtrip_pxor_xmm0_xmm1_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "pxor xmm0, xmm1",
        &[0x66, 0x0f, 0xef, 0xc1],
        I386Fixture {
            registers: vec![
                (I386Register::Rax, 0x1122_3344_5566_7788),
                (I386Register::Rbx, 0x3000),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2ff0),
                (
                    I386Register::Xmm0,
                    0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00,
                ),
                (
                    I386Register::Xmm1,
                    0xff00_ee11_dd22_cc33_bb44_aa55_9966_8877,
                ),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}
