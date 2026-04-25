use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn eon_semantics_match_unicorn_transitions() {
    let cases = [
(
            "eon x0, x1, x2",
            vec![0x20, 0x00, 0x22, 0xca],
            Arm64Fixture {
                registers: vec![("x1", 0xf0f0_0000_f0f0_0000), ("x2", 0x0ff0_0ff0_0ff0_0ff0)],
                memory: vec![],
            },
        ),
(
            "eon w0, w1, w2",
            vec![0x20, 0x00, 0x22, 0x4a],
            Arm64Fixture {
                registers: vec![("w1", 0xf0f0_0000), ("w2", 0x0ff0_0ff0)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
