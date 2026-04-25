use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn and_semantics_match_unicorn_transitions() {
    let cases = [
(
            "and x0, x1, x2",
            vec![0x20, 0x00, 0x02, 0x8a],
            Arm64Fixture {
                registers: vec![("x1", 0xf0f0_f0f0_f0f0_f0f0), ("x2", 0x0ff0_0ff0_0ff0_0ff0)],
                memory: vec![],
            },
        ),
(
            "and w0, w1, w2",
            vec![0x20, 0x00, 0x02, 0x0a],
            Arm64Fixture {
                registers: vec![("w1", 0xf0f0_f0f0), ("w2", 0x0ff0_0ff0)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
