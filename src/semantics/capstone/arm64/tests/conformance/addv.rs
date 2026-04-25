use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn addv_semantics_match_unicorn_transitions() {
    let cases = [
(
            "addv s0, v1.4s",
            vec![0x20, 0xb8, 0xb1, 0x4e],
            Arm64Fixture {
                registers: vec![("v1", 0x0000_0004_0000_0003_0000_0002_0000_0001u128)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
