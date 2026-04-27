use super::super::support::{
    I386Fixture, I386Register, assert_complete_semantics,
    assert_i386_instruction_roundtrip_match_unicorn, assert_i386_semantics_match_unicorn,
};
use crate::Architecture;

#[test]
fn cmps_semantics_stay_complete() {
    assert_complete_semantics("cmpsb", Architecture::I386, &[0xa6]);
    assert_complete_semantics("cmpsw", Architecture::I386, &[0x66, 0xa7]);
    assert_complete_semantics("cmpsd", Architecture::I386, &[0xa7]);
}

#[test]
fn cmps_semantics_match_unicorn_transitions() {
    let cases = [
        (
            "cmpsb",
            vec![0xa6],
            I386Fixture {
                registers: vec![(I386Register::Esi, 0x3500), (I386Register::Edi, 0x3600)],
                eflags: (1 << 1) | (1 << 10),
                memory: vec![(0x3500, vec![0x20]), (0x3600, vec![0x10])],
            },
        ),
        (
            "cmpsw",
            vec![0x66, 0xa7],
            I386Fixture {
                registers: vec![(I386Register::Esi, 0x3510), (I386Register::Edi, 0x3610)],
                eflags: 1 << 1,
                memory: vec![(0x3510, vec![0x34, 0x12]), (0x3610, vec![0x35, 0x12])],
            },
        ),
        (
            "cmpsd",
            vec![0xa7],
            I386Fixture {
                registers: vec![(I386Register::Esi, 0x3520), (I386Register::Edi, 0x3620)],
                eflags: 1 << 1,
                memory: vec![
                    (0x3520, vec![0x78, 0x56, 0x34, 0x12]),
                    (0x3620, vec![0x77, 0x56, 0x34, 0x12]),
                ],
            },
        ),
    ];

    for (name, bytes, fixture) in cases {
        assert_i386_semantics_match_unicorn(name, &bytes, fixture);
    }
}

#[test]
fn i386_roundtrip_cmpsb_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "cmpsb",
        &[0xa6],
        I386Fixture {
            registers: vec![
                (I386Register::Esi, 0x3500),
                (I386Register::Edi, 0x3600),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: (1 << 1) | (1 << 10),
            memory: vec![(0x3500, vec![0x20]), (0x3600, vec![0x10])],
        },
    );
}

#[test]
fn i386_roundtrip_cmpsw_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "cmpsw",
        &[0x66, 0xa7],
        I386Fixture {
            registers: vec![
                (I386Register::Esi, 0x3510),
                (I386Register::Edi, 0x3610),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: vec![(0x3510, vec![0x34, 0x12]), (0x3610, vec![0x35, 0x12])],
        },
    );
}

#[test]
fn i386_roundtrip_cmpsd_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "cmpsd",
        &[0xa7],
        I386Fixture {
            registers: vec![
                (I386Register::Esi, 0x3520),
                (I386Register::Edi, 0x3620),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: vec![
                (0x3520, vec![0x78, 0x56, 0x34, 0x12]),
                (0x3620, vec![0x77, 0x56, 0x34, 0x12]),
            ],
        },
    );
}
