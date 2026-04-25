use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn smsubl_semantics_match_unicorn_transitions() {
    let cases = [
(
            "smsubl x0, w1, w2, x3",
            vec![0x20, 0x8c, 0x22, 0x9b],
            Arm64Fixture {
                registers: vec![("w1", 0xffff_fffe), ("w2", 3), ("x3", 100)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
