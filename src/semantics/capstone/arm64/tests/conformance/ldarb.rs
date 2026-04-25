use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn ldarb_semantics_match_unicorn_transitions() {
    let cases = [
(
            "ldarb w0, [x1]",
            vec![0x20, 0xfc, 0xdf, 0x08],
            Arm64Fixture {
                registers: vec![("x1", 0x2000)],
                memory: vec![(0x2000, vec![0xab])],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
