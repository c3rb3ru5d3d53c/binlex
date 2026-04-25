use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn sub_semantics_match_unicorn_transitions() {
    let cases = [
(
            "sub x0, x1, x2",
            vec![0x20, 0x00, 0x02, 0xcb],
            Arm64Fixture {
                registers: vec![("x1", 7), ("x2", 3)],
                memory: vec![],
            },
        ),
(
            "sub w0, w1, w2",
            vec![0x20, 0x00, 0x02, 0x4b],
            Arm64Fixture {
                registers: vec![("w1", 7), ("w2", 3)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
