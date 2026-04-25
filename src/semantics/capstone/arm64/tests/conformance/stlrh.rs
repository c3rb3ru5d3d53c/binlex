use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn stlrh_semantics_match_unicorn_transitions() {
    let cases = [
(
            "stlrh w0, [x1]",
            vec![0x20, 0xfc, 0x9f, 0x48],
            Arm64Fixture {
                registers: vec![("w0", 0x1234_abcd), ("x1", 0x2000)],
                memory: vec![(0x2000, vec![0x00, 0x00])],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
