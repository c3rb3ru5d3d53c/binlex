use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn rev64_semantics_match_unicorn_transitions() {
    let cases = [
(
            "rev64 v0.16b, v1.16b",
            vec![0x20, 0x08, 0x20, 0x4e],
            Arm64Fixture {
                registers: vec![
                    ("v1", 0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00u128),
                ],
                memory: vec![],
            },
        ),
(
            "rev64 v0.2s, v1.2s",
            vec![0x20, 0x08, 0xa0, 0x0e],
            Arm64Fixture {
                registers: vec![("v1", 0x0000_0000_0000_0000_1122_3344_5566_7788u128)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
