use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn cmeq_semantics_match_unicorn_transitions() {
    let cases = [
(
            "cmeq v0.16b, v1.16b, v2.16b",
            vec![0x20, 0x8c, 0x22, 0x6e],
            Arm64Fixture {
                registers: vec![
                    ("v1", 0x100f_0e0d_0c0b_0a09_0807_0605_0403_0201u128),
                    ("v2", 0x1001_0e0d_0cff_0a09_aa07_0605_0400_0201u128),
                ],
                memory: vec![],
            },
        ),
(
            "cmeq v0.2s, v1.2s, v2.2s",
            vec![0x20, 0x8c, 0xa2, 0x2e],
            Arm64Fixture {
                registers: vec![
                    ("v1", 0x0000_0000_0000_0000_0000_0002_0000_0001u128),
                    ("v2", 0x0000_0000_0000_0000_0000_0003_0000_0001u128),
                ],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
