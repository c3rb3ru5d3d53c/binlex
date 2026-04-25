use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn ldrsw_semantics_match_unicorn_transitions() {
    let cases = [
(
            "ldrsw x0, [x1]",
            vec![0x20, 0x00, 0x80, 0xb9],
            Arm64Fixture {
                registers: vec![("x1", 0x2000)],
                memory: vec![(0x2000, vec![0x01, 0x00, 0x00, 0x80])],
            },
        ),
(
            "ldrsw x0, [x1, x2]",
            vec![0x20, 0x68, 0xa2, 0xb8],
            Arm64Fixture {
                registers: vec![("x1", 0x3000), ("x2", 0x10)],
                memory: vec![(0x3010, vec![0x01, 0x00, 0x00, 0x80])],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
