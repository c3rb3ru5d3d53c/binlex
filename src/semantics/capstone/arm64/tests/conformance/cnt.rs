use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn cnt_semantics_match_unicorn_transitions() {
    let cases = [
(
            "cnt v0.8b, v1.8b",
            vec![0x20, 0x58, 0x20, 0x0e],
            Arm64Fixture {
                registers: vec![("v1", 0x0000_0000_0000_0000_f0ff_5501_7f80_0000u128)],
                memory: vec![],
            },
        ),
(
            "cnt v0.16b, v1.16b",
            vec![0x20, 0x58, 0x20, 0x4e],
            Arm64Fixture {
                registers: vec![
                    ("v1", 0xf0ff_5501_7f80_0000_1122_3344_5566_7788u128),
                ],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
