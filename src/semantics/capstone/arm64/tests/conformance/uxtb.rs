use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn uxtb_semantics_match_unicorn_transitions() {
    let cases = [
(
            "uxtb w0, w1",
            vec![0x20, 0x1c, 0x00, 0x53],
            Arm64Fixture {
                registers: vec![("w1", 0x1234_56ab)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
