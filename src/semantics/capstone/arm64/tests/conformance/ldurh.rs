use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn ldurh_semantics_match_unicorn_transitions() {
    let cases = [
(
            "ldurh w0, [x1, #8]",
            vec![0x20, 0x80, 0x40, 0x78],
            Arm64Fixture {
                registers: vec![("x1", 0x3000)],
                memory: vec![(0x3008, vec![0xcd, 0xab])],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
