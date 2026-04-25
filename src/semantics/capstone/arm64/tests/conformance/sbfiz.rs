use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn sbfiz_semantics_match_unicorn_transitions() {
    let cases = [
(
            "sbfiz x0, x1, #4, #8",
            vec![0x20, 0x1c, 0x7c, 0x93],
            Arm64Fixture {
                registers: vec![("x1", 0x0000_0000_0000_00f1)],
                memory: vec![],
            },
        ),
(
            "sbfiz w0, w1, #4, #8",
            vec![0x20, 0x1c, 0x1c, 0x13],
            Arm64Fixture {
                registers: vec![("w1", 0x0000_00f1)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
