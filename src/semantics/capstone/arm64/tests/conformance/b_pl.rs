use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn b_pl_semantics_match_unicorn_transitions() {
    let cases = [
(
            "b.pl #0x10",
            vec![0x85, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("n", 0)],
                memory: vec![],
            },
        ),
(
            "b.pl #0x10",
            vec![0x85, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("n", 1)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
