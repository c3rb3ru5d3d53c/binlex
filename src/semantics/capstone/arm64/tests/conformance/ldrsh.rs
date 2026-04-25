use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn ldrsh_semantics_match_unicorn_transitions() {
    let cases = [
(
            "ldrsh x0, [x1]",
            vec![0x20, 0x00, 0x80, 0x79],
            Arm64Fixture {
                registers: vec![("x1", 0x2000)],
                memory: vec![(0x2000, vec![0x01, 0x80])],
            },
        ),
(
            "ldrsh x0, [x1, x2]",
            vec![0x20, 0x68, 0xa2, 0x78],
            Arm64Fixture {
                registers: vec![("x1", 0x3000), ("x2", 0x10)],
                memory: vec![(0x3010, vec![0x01, 0x80])],
            },
        ),
(
            "ldrsh w0, [x1, x2]",
            vec![0x20, 0x68, 0xe2, 0x78],
            Arm64Fixture {
                registers: vec![("x1", 0x3000), ("x2", 0x10)],
                memory: vec![(0x3010, vec![0x01, 0x80])],
            },
        ),
(
            "ldrsh w0, [x1]",
            vec![0x20, 0x00, 0xc0, 0x79],
            Arm64Fixture {
                registers: vec![("x1", 0x2000)],
                memory: vec![(0x2000, vec![0x01, 0x80])],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
