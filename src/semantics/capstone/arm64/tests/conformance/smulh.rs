use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn smulh_semantics_match_unicorn_transitions() {
    let cases = [
(
            "smulh x0, x1, x2",
            vec![0x20, 0x7c, 0x42, 0x9b],
            Arm64Fixture {
                registers: vec![("x1", 0xffff_ffff_ffff_fffe), ("x2", 3)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
