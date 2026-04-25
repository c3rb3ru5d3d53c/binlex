use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn sbc_semantics_match_unicorn_transitions() {
    let cases = [
(
            "sbc x0, x1, x2",
            vec![0x20, 0x00, 0x02, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 10), ("x2", 3), ("n", 0), ("z", 0), ("c", 1), ("v", 0)],
                memory: vec![],
            },
        ),
(
            "sbc w0, w1, w2",
            vec![0x20, 0x00, 0x02, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 10), ("w2", 3), ("n", 0), ("z", 0), ("c", 1), ("v", 0)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
