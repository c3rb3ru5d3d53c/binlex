use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn b_hi_semantics_match_unicorn_transitions() {
    let cases = [
(
            "b.hi #0x10",
            vec![0x88, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
(
            "b.hi #0x10",
            vec![0x88, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("c", 0), ("z", 0)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
