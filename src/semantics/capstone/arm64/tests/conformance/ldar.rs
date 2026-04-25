use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn ldar_semantics_match_unicorn_transitions() {
    let cases = [
(
            "ldar x0, [x1]",
            vec![0x20, 0xfc, 0xdf, 0xc8],
            Arm64Fixture {
                registers: vec![("x1", 0x3000)],
                memory: vec![(0x3000, vec![0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11])],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
