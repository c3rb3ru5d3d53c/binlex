use super::super::support::{
    I386Fixture, I386Register, assert_complete_semantics,
    assert_i386_instruction_roundtrip_match_unicorn,
};
use crate::Architecture;

#[test]
fn rcr_semantics_stay_complete() {
    let cases = [
        ("rcr eax, 1", Architecture::I386, vec![0xd1, 0xd8]),
        ("rcr rax, 1", Architecture::AMD64, vec![0x48, 0xd1, 0xd8]),
    ];

    for (name, architecture, bytes) in cases {
        assert_complete_semantics(name, architecture, &bytes);
    }
}

#[test]
fn i386_roundtrip_rcr_eax_1_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "rcr eax, 1",
        &[0xd1, 0xd8],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x8123_4567),
                (I386Register::Ebx, 0x5566_7788),
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
