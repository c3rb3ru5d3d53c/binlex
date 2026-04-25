use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn b_gt_semantics_match_unicorn_transitions() {
    let cases = [
(
            "b.gt #0x10",
            vec![0x8c, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("z", 0), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
(
            "b.gt #0x10",
            vec![0x8c, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("z", 1), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
