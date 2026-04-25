use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn umull_semantics_match_unicorn_transitions() {
    let cases = [
(
            "umull x0, w1, w2",
            vec![0x20, 0x7c, 0xa2, 0x9b],
            Arm64Fixture {
                registers: vec![("w1", 0xffff_ffff), ("w2", 2)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
