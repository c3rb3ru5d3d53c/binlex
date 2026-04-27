use super::super::support::{
    I386Fixture, I386Register, assert_complete_semantics,
    assert_i386_instruction_roundtrip_match_unicorn, assert_i386_semantics_match_unicorn,
};
use crate::Architecture;

#[test]
fn stos_semantics_stay_complete() {
    assert_complete_semantics("stosb", Architecture::I386, &[0xaa]);
    assert_complete_semantics("stosw", Architecture::I386, &[0x66, 0xab]);
    assert_complete_semantics("stosd", Architecture::I386, &[0xab]);
    assert_complete_semantics("rep stosd", Architecture::I386, &[0xf3, 0xab]);
    assert_complete_semantics("rep stosw", Architecture::I386, &[0xf3, 0x66, 0xab]);
}

#[test]
fn stos_semantics_match_unicorn_transitions() {
    let cases = [
        (
            "stosb",
            vec![0xaa],
            I386Fixture {
                registers: vec![
                    (I386Register::Eax, 0x0000_00ab),
                    (I386Register::Edi, 0x3000),
                ],
                eflags: (1 << 1) | (1 << 10),
                memory: vec![],
            },
        ),
        (
            "stosw",
            vec![0x66, 0xab],
            I386Fixture {
                registers: vec![
                    (I386Register::Eax, 0x0000_cdef),
                    (I386Register::Edi, 0x3010),
                ],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "stosd",
            vec![0xab],
            I386Fixture {
                registers: vec![
                    (I386Register::Eax, 0x1234_5678),
                    (I386Register::Edi, 0x3020),
                ],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "rep stosd",
            vec![0xf3, 0xab],
            I386Fixture {
                registers: vec![
                    (I386Register::Eax, 0x1122_3344),
                    (I386Register::Edi, 0x3700),
                    (I386Register::Ecx, 2),
                ],
                eflags: 1 << 1,
                memory: vec![],
            },
        ),
        (
            "rep stosw",
            vec![0xf3, 0x66, 0xab],
            I386Fixture {
                registers: vec![
                    (I386Register::Eax, 0x0000_abcd),
                    (I386Register::Edi, 0x3710),
                    (I386Register::Ecx, 2),
                ],
                eflags: (1 << 1) | (1 << 10),
                memory: vec![],
            },
        ),
    ];

    for (name, bytes, fixture) in cases {
        assert_i386_semantics_match_unicorn(name, &bytes, fixture);
    }
}

#[test]
fn i386_roundtrip_stosb_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "stosb",
        &[0xaa],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x0000_00ab),
                (I386Register::Edi, 0x3000),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: (1 << 1) | (1 << 10),
            memory: vec![(0x3000, vec![0x00])],
        },
    );
}

#[test]
fn i386_roundtrip_stosw_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "stosw",
        &[0x66, 0xab],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x0000_cdef),
                (I386Register::Edi, 0x3010),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: vec![(0x3010, vec![0x00, 0x00])],
        },
    );
}

#[test]
fn i386_roundtrip_stosd_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "stosd",
        &[0xab],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1234_5678),
                (I386Register::Edi, 0x3020),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: vec![(0x3020, vec![0x00, 0x00, 0x00, 0x00])],
        },
    );
}

#[test]
fn i386_roundtrip_rep_stosw_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "rep stosw",
        &[0xf3, 0x66, 0xab],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x0000_abcd),
                (I386Register::Edi, 0x3710),
                (I386Register::Ecx, 2),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: (1 << 1) | (1 << 10),
            memory: vec![(0x370c, vec![0x00, 0x00, 0x00, 0x00])],
        },
    );
}

#[test]
fn i386_roundtrip_rep_stosd_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "rep stosd",
        &[0xf3, 0xab],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1122_3344),
                (I386Register::Edi, 0x3700),
                (I386Register::Ecx, 2),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: vec![(0x3700, vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])],
        },
    );
}
