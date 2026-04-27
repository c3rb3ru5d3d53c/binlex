use super::super::support::{
    I386Fixture, I386Register, assert_complete_semantics,
    assert_i386_instruction_roundtrip_match_unicorn, assert_i386_semantics_match_unicorn,
};
use crate::Architecture;

#[test]
fn lods_semantics_stay_complete() {
    assert_complete_semantics("lodsb", Architecture::I386, &[0xac]);
    assert_complete_semantics("lodsw", Architecture::I386, &[0x66, 0xad]);
    assert_complete_semantics("lodsd", Architecture::I386, &[0xad]);
}

#[test]
fn lods_semantics_match_unicorn_transitions() {
    let cases = [
        (
            "lodsb",
            vec![0xac],
            I386Fixture {
                registers: vec![
                    (I386Register::Eax, 0xdead_beef),
                    (I386Register::Esi, 0x3300),
                ],
                eflags: (1 << 1) | (1 << 10),
                memory: vec![(0x3300, vec![0xaa])],
            },
        ),
        (
            "lodsw",
            vec![0x66, 0xad],
            I386Fixture {
                registers: vec![
                    (I386Register::Eax, 0xdead_beef),
                    (I386Register::Esi, 0x3310),
                ],
                eflags: 1 << 1,
                memory: vec![(0x3310, vec![0xef, 0xbe])],
            },
        ),
        (
            "lodsd",
            vec![0xad],
            I386Fixture {
                registers: vec![(I386Register::Eax, 0), (I386Register::Esi, 0x3320)],
                eflags: 1 << 1,
                memory: vec![(0x3320, vec![0x44, 0x33, 0x22, 0x11])],
            },
        ),
    ];

    for (name, bytes, fixture) in cases {
        assert_i386_semantics_match_unicorn(name, &bytes, fixture);
    }
}

#[test]
fn i386_roundtrip_lodsb_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "lodsb",
        &[0xac],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0xdead_beef),
                (I386Register::Esi, 0x3300),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: (1 << 1) | (1 << 10),
            memory: vec![(0x3300, vec![0xaa])],
        },
    );
}

#[test]
fn i386_roundtrip_lodsw_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "lodsw",
        &[0x66, 0xad],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0xdead_beef),
                (I386Register::Esi, 0x3310),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: vec![(0x3310, vec![0xef, 0xbe])],
        },
    );
}

#[test]
fn i386_roundtrip_lodsd_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "lodsd",
        &[0xad],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x0000_0000),
                (I386Register::Esi, 0x3320),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: vec![(0x3320, vec![0x44, 0x33, 0x22, 0x11])],
        },
    );
}
