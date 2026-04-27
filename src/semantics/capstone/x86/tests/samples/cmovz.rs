use super::super::support::{
    I386Fixture, I386Register, assert_amd64_instruction_roundtrip_match_unicorn,
    assert_i386_instruction_roundtrip_match_unicorn,
};

#[test]
fn i386_roundtrip_cmovz_eax_ebx_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "cmovz eax, ebx",
        &[0x0f, 0x44, 0xc3],
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
            ],
            eflags: 0x246,
            memory: vec![],
        },
    );
}

#[test]
fn amd64_roundtrip_cmovz_rax_rbx_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "cmovz rax, rbx",
        &[0x48, 0x0f, 0x44, 0xc3],
        I386Fixture {
            registers: vec![
                (I386Register::Rax, 0x1122_3344_5566_7788),
                (I386Register::Rbx, 0x8877_6655_4433_2211),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2ff0),
            ],
            eflags: 0x246,
            memory: vec![],
        },
    );
}
