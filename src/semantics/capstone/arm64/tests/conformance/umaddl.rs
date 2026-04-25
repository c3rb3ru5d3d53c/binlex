use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn umaddl_semantics_match_unicorn_transitions() {
    let cases = [
(
            "umaddl x0, w1, w2, x3",
            vec![0x20, 0x0c, 0xa2, 0x9b],
            Arm64Fixture {
                registers: vec![("w1", 7), ("w2", 6), ("x3", 5)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
