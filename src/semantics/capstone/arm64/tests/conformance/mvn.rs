use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn mvn_semantics_match_unicorn_transitions() {
    let cases = [
(
            "mvn x0, x1",
            vec![0xe0, 0x03, 0x21, 0xaa],
            Arm64Fixture {
                registers: vec![("x1", 0x00ff_00ff_00ff_00ff)],
                memory: vec![],
            },
        ),
(
            "mvn w0, w1",
            vec![0xe0, 0x03, 0x21, 0x2a],
            Arm64Fixture {
                registers: vec![("w1", 0x00ff_00ff)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
