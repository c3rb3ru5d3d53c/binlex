use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn ldtrsw_semantics_match_unicorn_transitions() {
    let cases = [
(
            "ldtrsw x0, [x1, #8]",
            vec![0x20, 0x88, 0x80, 0xb8],
            Arm64Fixture {
                registers: vec![("x1", 0x3000)],
                memory: vec![(0x3008, vec![0x01, 0x00, 0x00, 0x80])],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
