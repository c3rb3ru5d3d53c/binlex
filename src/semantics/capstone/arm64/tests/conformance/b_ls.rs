use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn b_ls_semantics_match_unicorn_transitions() {
    let cases = [
(
            "b.ls #0x10",
            vec![0x89, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
(
            "b.ls #0x10",
            vec![0x89, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("c", 1), ("z", 0)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
