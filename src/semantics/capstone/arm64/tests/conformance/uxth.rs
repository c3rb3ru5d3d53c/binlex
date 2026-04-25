use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn uxth_semantics_match_unicorn_transitions() {
    let cases = [
(
            "uxth w0, w1",
            vec![0x20, 0x3c, 0x00, 0x53],
            Arm64Fixture {
                registers: vec![("w1", 0x1234_abcd)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
