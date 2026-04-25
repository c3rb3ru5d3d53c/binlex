use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn b_ne_semantics_match_unicorn_transitions() {
    let cases = [
(
            "b.ne #0x10",
            vec![0x81, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("z", 0)],
                memory: vec![],
            },
        ),
(
            "b.ne #0x10",
            vec![0x81, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("z", 1)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
