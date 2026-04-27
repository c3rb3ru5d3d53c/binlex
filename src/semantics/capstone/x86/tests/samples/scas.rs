use super::super::support::{
    I386Fixture, I386Register, assert_complete_semantics,
    assert_i386_instruction_roundtrip_match_unicorn, assert_i386_semantics_match_unicorn,
};
use crate::Architecture;

#[test]
fn scas_semantics_stay_complete() {
    assert_complete_semantics("scasb", Architecture::I386, &[0xae]);
    assert_complete_semantics("scasw", Architecture::I386, &[0x66, 0xaf]);
    assert_complete_semantics("scasd", Architecture::I386, &[0xaf]);
}

#[test]
fn scas_semantics_match_unicorn_transitions() {
    let cases = [
        (
            "scasb",
            vec![0xae],
            I386Fixture {
                registers: vec![
                    (I386Register::Eax, 0x0000_0041),
                    (I386Register::Edi, 0x3400),
                ],
                eflags: (1 << 1) | (1 << 10),
                memory: vec![(0x3400, vec![0x41])],
            },
        ),
        (
            "scasw",
            vec![0x66, 0xaf],
            I386Fixture {
                registers: vec![
                    (I386Register::Eax, 0x0000_1234),
                    (I386Register::Edi, 0x3410),
                ],
                eflags: 1 << 1,
                memory: vec![(0x3410, vec![0x34, 0x12])],
            },
        ),
        (
            "scasd",
            vec![0xaf],
            I386Fixture {
                registers: vec![
                    (I386Register::Eax, 0x1234_5678),
                    (I386Register::Edi, 0x3420),
                ],
                eflags: 1 << 1,
                memory: vec![(0x3420, vec![0x79, 0x56, 0x34, 0x12])],
            },
        ),
    ];

    for (name, bytes, fixture) in cases {
        assert_i386_semantics_match_unicorn(name, &bytes, fixture);
    }
}

#[test]
fn i386_roundtrip_scasb_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "scasb",
        &[0xae],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x0000_0041),
                (I386Register::Edi, 0x3400),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: (1 << 1) | (1 << 10),
            memory: vec![(0x3400, vec![0x41])],
        },
    );
}

#[test]
fn i386_roundtrip_scasw_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "scasw",
        &[0x66, 0xaf],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x0000_1234),
                (I386Register::Edi, 0x3410),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: vec![(0x3410, vec![0x34, 0x12])],
        },
    );
}

#[test]
fn i386_roundtrip_scasd_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "scasd",
        &[0xaf],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1234_5678),
                (I386Register::Edi, 0x3420),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: vec![(0x3420, vec![0x79, 0x56, 0x34, 0x12])],
        },
    );
}
