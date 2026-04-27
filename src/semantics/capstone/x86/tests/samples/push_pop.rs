use super::super::support::{
    I386Fixture, I386Register, assert_complete_semantics,
    assert_i386_instruction_roundtrip_match_unicorn, assert_i386_semantics_match_unicorn,
};
use crate::Architecture;

#[test]
fn pushal_semantics_stay_complete() {
    assert_complete_semantics("pushal", Architecture::I386, &[0x60]);
}

#[test]
fn popal_semantics_stay_complete() {
    assert_complete_semantics("popal", Architecture::I386, &[0x61]);
}

#[test]
fn push_pop_semantics_match_unicorn_transitions() {
    let cases = [
        (
            "push eax",
            vec![0x50],
            I386Fixture {
                registers: vec![
                    (I386Register::Eax, 0x1234_5678),
                    (I386Register::Esp, 0x2800),
                ],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "pop eax",
            vec![0x58],
            I386Fixture {
                registers: vec![
                    (I386Register::Eax, 0xdead_beef),
                    (I386Register::Esp, 0x2800),
                ],
                eflags: 1 << 1,
                memory: vec![(0x2800, vec![0x78, 0x56, 0x34, 0x12])],
            },
        ),
        (
            "pushal",
            vec![0x60],
            I386Fixture {
                registers: vec![
                    (I386Register::Eax, 0x1111_1111),
                    (I386Register::Ecx, 0x2222_2222),
                    (I386Register::Edx, 0x3333_3333),
                    (I386Register::Ebx, 0x4444_4444),
                    (I386Register::Esp, 0x2840),
                    (I386Register::Ebp, 0x5555_5555),
                    (I386Register::Esi, 0x6666_6666),
                    (I386Register::Edi, 0x7777_7777),
                ],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "popal",
            vec![0x61],
            I386Fixture {
                registers: vec![
                    (I386Register::Eax, 0),
                    (I386Register::Ecx, 0),
                    (I386Register::Edx, 0),
                    (I386Register::Ebx, 0),
                    (I386Register::Esp, 0x2800),
                    (I386Register::Ebp, 0),
                    (I386Register::Esi, 0),
                    (I386Register::Edi, 0),
                ],
                eflags: 1 << 1,
                memory: vec![(
                    0x2800,
                    vec![
                        0x77, 0x77, 0x77, 0x77, 0x66, 0x66, 0x66, 0x66, 0x55, 0x55, 0x55,
                        0x55, 0x40, 0x28, 0x00, 0x00, 0x44, 0x44, 0x44, 0x44, 0x33, 0x33,
                        0x33, 0x33, 0x22, 0x22, 0x22, 0x22, 0x11, 0x11, 0x11, 0x11,
                    ],
                )],
            },
        ),
    ];

    for (name, bytes, fixture) in cases {
        assert_i386_semantics_match_unicorn(name, &bytes, fixture);
    }
}

#[test]
fn i386_roundtrip_push_eax_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "push eax",
        &[0x50],
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
            memory: vec![(0x2fec, vec![0xaa, 0xbb, 0xcc, 0xdd])],
        },
    );
}

#[test]
fn i386_roundtrip_pop_eax_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "pop eax",
        &[0x58],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1122_3344),
                (I386Register::Ebx, 0x5566_7788),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fec),
            ],
            eflags: 0x246,
            memory: vec![(0x2fec, vec![0x78, 0x56, 0x34, 0x12])],
        },
    );
}

#[test]
fn i386_roundtrip_pushfd_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "pushfd",
        &[0x9c],
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
            memory: vec![(0x2fec, vec![0xaa, 0xbb, 0xcc, 0xdd])],
        },
    );
}

#[test]
fn i386_roundtrip_popfd_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "popfd",
        &[0x9d],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1122_3344),
                (I386Register::Ebx, 0x5566_7788),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fec),
            ],
            eflags: 0x202,
            memory: vec![(0x2fec, vec![0x46, 0x02, 0x00, 0x00])],
        },
    );
}
