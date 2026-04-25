use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn madd_semantics_match_unicorn_transitions() {
    let cases = [
(
            "madd x0, x1, x2, x3",
            vec![0x20, 0x0c, 0x02, 0x9b],
            Arm64Fixture {
                registers: vec![("x1", 7), ("x2", 6), ("x3", 5)],
                memory: vec![],
            },
        ),
(
            "madd w0, w1, w2, w3",
            vec![0x20, 0x0c, 0x02, 0x1b],
            Arm64Fixture {
                registers: vec![("w1", 7), ("w2", 6), ("w3", 5)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
