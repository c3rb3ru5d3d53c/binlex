use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn uaddlv_semantics_match_unicorn_transitions() {
    let cases = [
(
            "uaddlv h0, v1.8b",
            vec![0x20, 0x38, 0x30, 0x2e],
            Arm64Fixture {
                registers: vec![("v1", 0x0000_0000_0000_0000_0807_0605_0403_0201u128)],
                memory: vec![],
            },
        ),
(
            "uaddlv h0, v1.16b",
            vec![0x20, 0x38, 0x30, 0x6e],
            Arm64Fixture {
                registers: vec![
                    ("v1", 0x100f_0e0d_0c0b_0a09_0807_0605_0403_0201u128),
                ],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
