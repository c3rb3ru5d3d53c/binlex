use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn neg_semantics_match_unicorn_transitions() {
    let cases = [
(
            "neg x0, x1",
            vec![0xe0, 0x03, 0x01, 0xcb],
            Arm64Fixture {
                registers: vec![("x1", 5)],
                memory: vec![],
            },
        ),
(
            "neg w0, w1",
            vec![0xe0, 0x03, 0x01, 0x4b],
            Arm64Fixture {
                registers: vec![("w1", 5)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
