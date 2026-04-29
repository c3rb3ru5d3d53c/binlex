use super::super::support::{
    I386Fixture, I386Register, assert_i386_instruction_roundtrip_match_unicorn,
};

#[test]
fn imul_roundtrip_i386_two_operand_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "imul eax, ebx",
        &[0x0f, 0xaf, 0xc3],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0xffff_fff0),
                (I386Register::Ebx, 5),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn imul_roundtrip_i386_one_operand_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "imul ecx",
        &[0xf7, 0xe9],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0xffff_fff0),
                (I386Register::Ecx, 5),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}
