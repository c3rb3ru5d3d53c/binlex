use super::super::support::{
    I386Fixture, I386Register, assert_complete_semantics,
    assert_i386_instruction_roundtrip_match_unicorn, assert_i386_semantics_match_unicorn,
};
use crate::Architecture;

#[test]
fn movs_semantics_stay_complete() {
    assert_complete_semantics("movsb", Architecture::I386, &[0xa4]);
    assert_complete_semantics("movsw", Architecture::I386, &[0x66, 0xa5]);
    assert_complete_semantics("movsd", Architecture::I386, &[0xa5]);
    assert_complete_semantics("rep movsb", Architecture::I386, &[0xf3, 0xa4]);
    assert_complete_semantics("rep movsw", Architecture::I386, &[0xf3, 0x66, 0xa5]);
    assert_complete_semantics("rep movsd", Architecture::I386, &[0xf3, 0xa5]);
}

#[test]
fn movs_semantics_match_unicorn_transitions() {
    let cases = [
        (
            "movsb",
            vec![0xa4],
            I386Fixture {
                registers: vec![(I386Register::Esi, 0x3100), (I386Register::Edi, 0x3200)],
                eflags: (1 << 1) | (1 << 10),
                memory: vec![(0x3100, vec![0x41])],
            },
        ),
        (
            "movsw",
            vec![0x66, 0xa5],
            I386Fixture {
                registers: vec![(I386Register::Esi, 0x3110), (I386Register::Edi, 0x3210)],
                eflags: 1 << 1,
                memory: vec![(0x3110, vec![0x34, 0x12])],
            },
        ),
        (
            "movsd",
            vec![0xa5],
            I386Fixture {
                registers: vec![(I386Register::Esi, 0x3120), (I386Register::Edi, 0x3220)],
                eflags: 1 << 1,
                memory: vec![(0x3120, vec![0x78, 0x56, 0x34, 0x12])],
            },
        ),
        (
            "rep movsb",
            vec![0xf3, 0xa4],
            I386Fixture {
                registers: vec![
                    (I386Register::Esi, 0x3800),
                    (I386Register::Edi, 0x3900),
                    (I386Register::Ecx, 3),
                ],
                eflags: 1 << 1,
                memory: vec![(0x3800, vec![0x41, 0x42, 0x43])],
            },
        ),
        (
            "rep movsw",
            vec![0xf3, 0x66, 0xa5],
            I386Fixture {
                registers: vec![
                    (I386Register::Esi, 0x3810),
                    (I386Register::Edi, 0x3910),
                    (I386Register::Ecx, 2),
                ],
                eflags: (1 << 1) | (1 << 10),
                memory: vec![(0x380e, vec![0xaa, 0xbb, 0xcc, 0xdd])],
            },
        ),
        (
            "rep movsd",
            vec![0xf3, 0xa5],
            I386Fixture {
                registers: vec![
                    (I386Register::Esi, 0x3820),
                    (I386Register::Edi, 0x3920),
                    (I386Register::Ecx, 2),
                ],
                eflags: 1 << 1,
                memory: vec![(0x3820, vec![0x01, 0x02, 0x03, 0x04, 0x11, 0x12, 0x13, 0x14])],
            },
        ),
    ];

    for (name, bytes, fixture) in cases {
        assert_i386_semantics_match_unicorn(name, &bytes, fixture);
    }
}

#[test]
fn i386_roundtrip_movsb_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movsb",
        &[0xa4],
        I386Fixture {
            registers: vec![
                (I386Register::Esi, 0x3100),
                (I386Register::Edi, 0x3200),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: (1 << 1) | (1 << 10),
            memory: vec![(0x3100, vec![0x41]), (0x3200, vec![0x00])],
        },
    );
}

#[test]
fn i386_roundtrip_movsw_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movsw",
        &[0x66, 0xa5],
        I386Fixture {
            registers: vec![
                (I386Register::Esi, 0x3110),
                (I386Register::Edi, 0x3210),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: vec![(0x3110, vec![0x34, 0x12]), (0x3210, vec![0x00, 0x00])],
        },
    );
}

#[test]
fn i386_roundtrip_movsd_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "movsd",
        &[0xa5],
        I386Fixture {
            registers: vec![
                (I386Register::Esi, 0x3120),
                (I386Register::Edi, 0x3220),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: vec![
                (0x3120, vec![0x78, 0x56, 0x34, 0x12]),
                (0x3220, vec![0x00, 0x00, 0x00, 0x00]),
            ],
        },
    );
}

#[test]
fn i386_roundtrip_rep_movsb_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "rep movsb",
        &[0xf3, 0xa4],
        I386Fixture {
            registers: vec![
                (I386Register::Esi, 0x3800),
                (I386Register::Edi, 0x3900),
                (I386Register::Ecx, 3),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: vec![
                (0x3800, vec![0x41, 0x42, 0x43]),
                (0x3900, vec![0x00, 0x00, 0x00]),
            ],
        },
    );
}

#[test]
fn i386_roundtrip_rep_movsw_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "rep movsw",
        &[0xf3, 0x66, 0xa5],
        I386Fixture {
            registers: vec![
                (I386Register::Esi, 0x3810),
                (I386Register::Edi, 0x3910),
                (I386Register::Ecx, 2),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: (1 << 1) | (1 << 10),
            memory: vec![
                (0x380e, vec![0xaa, 0xbb, 0xcc, 0xdd]),
                (0x390c, vec![0x00, 0x00, 0x00, 0x00]),
            ],
        },
    );
}

#[test]
fn i386_roundtrip_rep_movsd_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "rep movsd",
        &[0xf3, 0xa5],
        I386Fixture {
            registers: vec![
                (I386Register::Esi, 0x3820),
                (I386Register::Edi, 0x3920),
                (I386Register::Ecx, 2),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2fc0),
            ],
            eflags: 1 << 1,
            memory: vec![
                (0x3820, vec![0x01, 0x02, 0x03, 0x04, 0x11, 0x12, 0x13, 0x14]),
                (0x3920, vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            ],
        },
    );
}
