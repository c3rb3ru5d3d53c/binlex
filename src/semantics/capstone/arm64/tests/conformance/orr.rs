use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn orr_semantics_match_unicorn_transitions() {
    let cases = [
(
            "orr x0, x1, x2",
            vec![0x20, 0x00, 0x02, 0xaa],
            Arm64Fixture {
                registers: vec![("x1", 0xf0f0_0000_f0f0_0000), ("x2", 0x0000_0ff0_0000_0ff0)],
                memory: vec![],
            },
        ),
(
            "orr w0, w1, w2",
            vec![0x20, 0x00, 0x02, 0x2a],
            Arm64Fixture {
                registers: vec![("w1", 0xf0f0_0000), ("w2", 0x0000_0ff0)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
