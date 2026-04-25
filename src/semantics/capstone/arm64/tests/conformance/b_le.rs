use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn b_le_semantics_match_unicorn_transitions() {
    let cases = [
(
            "b.le #0x10",
            vec![0x8d, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("z", 1), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
(
            "b.le #0x10",
            vec![0x8d, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("z", 0), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
