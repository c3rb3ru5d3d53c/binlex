use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn ldpsw_semantics_match_unicorn_transitions() {
    let cases = [
(
            "ldpsw x0, x1, [x2]",
            vec![0x40, 0x04, 0x40, 0x69],
            Arm64Fixture {
                registers: vec![("x2", 0x3000)],
                memory: vec![(
                    0x3000,
                    vec![
                        0x01, 0x00, 0x00, 0x80, 0xfe, 0xff, 0xff, 0xff,
                    ],
                )],
            },
        ),
(
            "ldpsw x0, x1, [x2], #8",
            vec![0x40, 0x04, 0xc1, 0x68],
            Arm64Fixture {
                registers: vec![("x2", 0x3000)],
                memory: vec![(
                    0x3000,
                    vec![0x01, 0x00, 0x00, 0x80, 0xfe, 0xff, 0xff, 0xff],
                )],
            },
        ),
(
            "ldpsw x0, x1, [sp, #-8]!",
            vec![0xe0, 0x07, 0xff, 0x69],
            Arm64Fixture {
                registers: vec![("sp", 0x2ff0)],
                memory: vec![(
                    0x2fe8,
                    vec![0x01, 0x00, 0x00, 0x80, 0xfe, 0xff, 0xff, 0xff],
                )],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
