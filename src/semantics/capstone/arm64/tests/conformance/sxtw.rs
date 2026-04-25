use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn sxtw_semantics_match_unicorn_transitions() {
    let cases = [
(
            "sxtw x0, w1",
            vec![0x20, 0x7c, 0x40, 0x93],
            Arm64Fixture {
                registers: vec![("w1", 0x8000_0001)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
