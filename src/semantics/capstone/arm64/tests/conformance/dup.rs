use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn dup_semantics_match_unicorn_transitions() {
    let cases = [
(
            "dup v0.2d, x1",
            vec![0x20, 0x0c, 0x08, 0x4e],
            Arm64Fixture {
                registers: vec![("x1", 0x1122_3344_5566_7788)],
                memory: vec![],
            },
        ),
(
            "dup v0.16b, w1",
            vec![0x20, 0x0c, 0x01, 0x4e],
            Arm64Fixture {
                registers: vec![("w1", 0x1234_56ab)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
