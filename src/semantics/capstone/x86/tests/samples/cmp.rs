use super::super::support::{
    I386Fixture, I386Register, assert_amd64_instruction_roundtrip_match_unicorn,
    assert_complete_semantics, assert_i386_instruction_roundtrip_match_unicorn,
    assert_i386_semantics_match_unicorn,
};
use crate::Architecture;

#[test]
fn cmp_semantics_stay_complete() {
    assert_complete_semantics("cmp eax, ebx", Architecture::I386, &[0x39, 0xd8]);
}

#[test]
fn cmp_semantics_match_unicorn_transitions() {
    assert_i386_semantics_match_unicorn(
        "cmp eax, ebx",
        &[0x39, 0xd8],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x8000_0000),
                (I386Register::Ebx, 0x0000_0001),
            ],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_cmp_eax_ebx_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "cmp eax, ebx",
        &[0x39, 0xd8],
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
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn amd64_roundtrip_cmp_rax_rbx_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "cmp rax, rbx",
        &[0x48, 0x39, 0xd8],
        I386Fixture {
            registers: vec![
                (I386Register::Rax, 0x1122_3344_5566_7788),
                (I386Register::Rbx, 0x0102_0304_0506_0708),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2ff0),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}
