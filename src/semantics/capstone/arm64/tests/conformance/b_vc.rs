use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn b_vc_semantics_match_unicorn_transitions() {
    let cases = [
(
            "b.vc #0x10",
            vec![0x87, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("v", 0)],
                memory: vec![],
            },
        ),
(
            "b.vc #0x10",
            vec![0x87, 0x00, 0x00, 0x54],
            Arm64Fixture {
                registers: vec![("v", 1)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
