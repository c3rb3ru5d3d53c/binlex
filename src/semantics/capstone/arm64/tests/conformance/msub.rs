use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn msub_semantics_match_unicorn_transitions() {
    let cases = [
(
            "msub x0, x1, x2, x3",
            vec![0x20, 0x8c, 0x02, 0x9b],
            Arm64Fixture {
                registers: vec![("x1", 7), ("x2", 6), ("x3", 100)],
                memory: vec![],
            },
        ),
(
            "msub w0, w1, w2, w3",
            vec![0x20, 0x8c, 0x02, 0x1b],
            Arm64Fixture {
                registers: vec![("w1", 7), ("w2", 6), ("w3", 100)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
