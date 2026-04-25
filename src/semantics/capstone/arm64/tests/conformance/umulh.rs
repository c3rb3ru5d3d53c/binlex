use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn umulh_semantics_match_unicorn_transitions() {
    let cases = [
(
            "umulh x0, x1, x2",
            vec![0x20, 0x7c, 0xc2, 0x9b],
            Arm64Fixture {
                registers: vec![("x1", 0xffff_ffff_ffff_ffff), ("x2", 2)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
