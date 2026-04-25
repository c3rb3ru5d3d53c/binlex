use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn sbfx_semantics_match_unicorn_transitions() {
    let cases = [
(
            "sbfx x0, x1, #4, #8",
            vec![0x20, 0x2c, 0x44, 0x93],
            Arm64Fixture {
                registers: vec![("x1", 0x0000_0000_0000_0ff0)],
                memory: vec![],
            },
        ),
(
            "sbfx w0, w1, #4, #8",
            vec![0x20, 0x2c, 0x04, 0x13],
            Arm64Fixture {
                registers: vec![("w1", 0x0000_0ff0)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
