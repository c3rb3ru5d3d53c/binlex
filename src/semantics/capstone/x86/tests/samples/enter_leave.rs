use super::super::support::{
    I386Fixture, I386Register, assert_complete_semantics,
    assert_i386_instruction_roundtrip_match_unicorn, assert_i386_semantics_match_unicorn,
};
use crate::Architecture;

#[test]
fn enter_semantics_stay_complete() {
    assert_complete_semantics(
        "enter 0x10, 0x00",
        Architecture::I386,
        &[0xc8, 0x10, 0x00, 0x00],
    );
    assert_complete_semantics(
        "enter 0x10, 0x01",
        Architecture::I386,
        &[0xc8, 0x10, 0x00, 0x01],
    );
}

#[test]
fn enter_leave_semantics_match_unicorn_transitions() {
    let cases = [
        (
            "leave",
            vec![0xc9],
            I386Fixture {
                registers: vec![(I386Register::Esp, 0x2900), (I386Register::Ebp, 0x2800)],
                eflags: 1 << 1,
                memory: vec![(0x2800, vec![0x44, 0x33, 0x22, 0x11])],
            },
        ),
        (
            "enter 0x10, 0x00",
            vec![0xc8, 0x10, 0x00, 0x00],
            I386Fixture {
                registers: vec![(I386Register::Esp, 0x2900), (I386Register::Ebp, 0x2800)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "enter 0x10, 0x01",
            vec![0xc8, 0x10, 0x00, 0x01],
            I386Fixture {
                registers: vec![(I386Register::Esp, 0x2900), (I386Register::Ebp, 0x2800)],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
    ];

    for (name, bytes, fixture) in cases {
        assert_i386_semantics_match_unicorn(name, &bytes, fixture);
    }
}

#[test]
fn i386_roundtrip_leave_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "leave",
        &[0xc9],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1122_3344),
                (I386Register::Ebx, 0x5566_7788),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Ebp, 0x2fe0),
                (I386Register::Esp, 0x2fd0),
            ],
            eflags: 0x246,
            memory: vec![(0x2fe0, vec![0xf0, 0x2f, 0x00, 0x00])],
        },
    );
}
