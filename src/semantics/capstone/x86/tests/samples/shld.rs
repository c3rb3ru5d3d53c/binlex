use super::super::support::{
    I386Fixture, I386Register, assert_complete_semantics,
    assert_i386_instruction_roundtrip_match_unicorn,
};
use crate::Architecture;

#[test]
fn shld_semantics_stay_complete() {
    assert_complete_semantics(
        "shld eax, edx, cl",
        Architecture::I386,
        &[0x0f, 0xa5, 0xd0],
    );
}

#[test]
fn i386_roundtrip_shld_eax_edx_4_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "shld eax, edx, 4",
        &[0x0f, 0xa4, 0xd0, 0x04],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1122_3344),
                (I386Register::Edx, 0x5566_7788),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_shld_eax_edx_cl_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "shld eax, edx, cl",
        &[0x0f, 0xa5, 0xd0],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1122_3344),
                (I386Register::Ecx, 0x0000_0004),
                (I386Register::Edx, 0x5566_7788),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}
