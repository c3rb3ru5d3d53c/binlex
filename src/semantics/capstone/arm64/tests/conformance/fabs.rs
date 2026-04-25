use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn fabs_semantics_match_unicorn_transitions() {
    let cases = [
(
            "fabs d0, d1",
            vec![0x20, 0xc0, 0x60, 0x1e],
            Arm64Fixture {
                registers: vec![("d1", 0xc008_0000_0000_0000)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
