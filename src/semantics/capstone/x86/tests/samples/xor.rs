use super::super::support::{
    I386Fixture, I386Register, assert_amd64_instruction_roundtrip_match_unicorn,
};

#[test]
fn xor_roundtrip_amd64_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "xor eax, eax",
        &[0x31, 0xc0],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1122_3344),
                (I386Register::Rax, 0x1122_3344),
                (I386Register::Ebx, 0x5566_7788),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
                (I386Register::Rsp, 0x2ff0),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}
