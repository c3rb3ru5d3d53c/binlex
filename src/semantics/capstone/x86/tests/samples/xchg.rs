use super::super::support::{
    I386Fixture, I386Register, assert_i386_instruction_roundtrip_match_unicorn,
};

#[test]
fn xchg_roundtrip_i386_register_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "xchg eax, ebx",
        &[0x93],
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
fn xchg_roundtrip_i386_memory_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "xchg dword ptr [ebx+4], eax",
        &[0x87, 0x43, 0x04],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1122_3344),
                (I386Register::Ebx, 0x3000),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 0x246,
            memory: vec![(0x3004, vec![0x88, 0x77, 0x66, 0x55])],
        },
    );
}
