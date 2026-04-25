use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn fnmul_semantics_match_unicorn_transitions() {
    let cases = [
(
            "fnmul d0, d1, d2",
            vec![0x20, 0x88, 0x62, 0x1e],
            Arm64Fixture {
                registers: vec![
                    ("d1", 0x4008_0000_0000_0000),
                    ("d2", 0x4014_0000_0000_0000),
                ],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
