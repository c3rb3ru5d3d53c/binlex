use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn b_semantics_match_unicorn_transitions() {
    let cases = [
        (
            "b #0x10",
            vec![0x04, 0x00, 0x00, 0x14],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
        (
            "b #0x20",
            vec![0x08, 0x00, 0x00, 0x14],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
