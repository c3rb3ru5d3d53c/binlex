use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn ucvtf_semantics_match_unicorn_transitions() {
    let cases = [
(
            "ucvtf d0, x1",
            vec![0x20, 0x00, 0x63, 0x9e],
            Arm64Fixture {
                registers: vec![("x1", 42)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
