use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn b_cs_semantics_match_unicorn_transitions() {
    let cases = [
(
            "b.cs #0x10",
            vec![0x82, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("c", 1)],
                memory: vec![],
            },
        ),
(
            "b.cs #0x10",
            vec![0x82, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("c", 0)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
