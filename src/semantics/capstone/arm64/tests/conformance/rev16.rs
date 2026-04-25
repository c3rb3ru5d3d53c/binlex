use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn rev16_semantics_match_unicorn_transitions() {
    let cases = [
(
            "rev16 x0, x1",
            vec![0x20, 0x04, 0xc0, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 0x1122_3344_5566_7788)],
                memory: vec![],
            },
        ),
(
            "rev16 w0, w1",
            vec![0x20, 0x04, 0xc0, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 0x1122_3344)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
