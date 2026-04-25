use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn stur_semantics_match_unicorn_transitions() {
    let cases = [
(
            "stur x0, [x1, #8]",
            vec![0x20, 0x80, 0x00, 0xf8],
            Arm64Fixture {
                registers: vec![("x0", 0x1122_3344_5566_7788), ("x1", 0x3000)],
                memory: vec![(0x3008, vec![0; 8])],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
