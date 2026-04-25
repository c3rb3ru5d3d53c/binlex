use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn clz_semantics_match_unicorn_transitions() {
    let cases = [
(
            "clz x0, x1",
            vec![0x20, 0x10, 0xc0, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 0x0000_0000_0000_00f0)],
                memory: vec![],
            },
        ),
(
            "clz w0, w1",
            vec![0x20, 0x10, 0xc0, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 0x0000_00f0)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
