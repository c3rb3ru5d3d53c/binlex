use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn movi_semantics_match_unicorn_transitions() {
    let cases = [
(
            "movi v0.16b, #0",
            vec![0x00, 0xe4, 0x00, 0x4f],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
(
            "movi v0.8b, #255",
            vec![0xe0, 0xe7, 0x07, 0x0f],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
(
            "movi v1.16b, #255",
            vec![0xe1, 0xe7, 0x07, 0x4f],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
(
            "movi v1.8b, #1",
            vec![0x21, 0xe4, 0x00, 0x0f],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
(
            "movi v0.2d, #0000000000000000",
            vec![0x00, 0xe4, 0x00, 0x6f],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
(
            "movi v0.2d, #0xffffffffffffffff",
            vec![0xe0, 0xe7, 0x07, 0x6f],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
(
            "movi v0.2s, #1",
            vec![0x20, 0x04, 0x00, 0x0f],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
(
            "movi v0.2s, #2",
            vec![0x40, 0x04, 0x00, 0x0f],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
(
            "movi d0, #0000000000000000",
            vec![0x00, 0xe4, 0x00, 0x2f],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
(
            "movi d0, #0xffffffffffffffff",
            vec![0xe0, 0xe7, 0x07, 0x2f],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
(
            "movi v2.2d, #0xffffffffffffffff",
            vec![0xe2, 0xe7, 0x07, 0x6f],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
