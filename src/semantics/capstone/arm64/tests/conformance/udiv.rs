use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn udiv_semantics_match_unicorn_transitions() {
    let cases = [
(
            "udiv x0, x1, x2",
            vec![0x20, 0x08, 0xc2, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 100), ("x2", 5)],
                memory: vec![],
            },
        ),
(
            "udiv w0, w1, w2",
            vec![0x20, 0x08, 0xc2, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 100), ("w2", 5)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
