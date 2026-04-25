use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn fmadd_semantics_match_unicorn_transitions() {
    let cases = [
(
            "fmadd d0, d1, d2, d3",
            vec![0x20, 0x0c, 0x42, 0x1f],
            Arm64Fixture {
                registers: vec![
                    ("d1", 0x4000_0000_0000_0000),
                    ("d2", 0x4014_0000_0000_0000),
                    ("d3", 0x4008_0000_0000_0000),
                ],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
