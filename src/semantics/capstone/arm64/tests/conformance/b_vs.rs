use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn b_vs_semantics_match_unicorn_transitions() {
    let cases = [
(
            "b.vs #0x10",
            vec![0x86, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("v", 1)],
                memory: vec![],
            },
        ),
(
            "b.vs #0x10",
            vec![0x86, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("v", 0)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
