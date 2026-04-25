use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn sturb_semantics_match_unicorn_transitions() {
    let cases = [
(
            "sturb w0, [x1, #8]",
            vec![0x20, 0x80, 0x00, 0x38],
            Arm64Fixture {
                registers: vec![("w0", 0x1234_56ab), ("x1", 0x3000)],
                memory: vec![(0x3008, vec![0x00])],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
