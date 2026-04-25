use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn adrp_semantics_match_unicorn_transitions() {
    let cases = [
(
            "adrp x0, #0",
            vec![0x00, 0x00, 0x00, 0x90],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
