use super::super::support::{I386Fixture, I386Register, assert_i386_instruction_roundtrip_match_unicorn};

#[test]
fn i386_roundtrip_setl_al_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "setl al",
        &[0x0f, 0x9c, 0xc0],
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
            eflags: 0x882,
            memory: vec![],
        },
    );
}
