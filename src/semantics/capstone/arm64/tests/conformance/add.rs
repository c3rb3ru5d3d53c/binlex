use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn add_semantics_match_unicorn_transitions() {
    let cases = [
(
            "add x0, x1, x2",
            vec![0x20, 0x00, 0x02, 0x8b],
            Arm64Fixture {
                registers: vec![("x1", 0x7fff_ffff_ffff_ffff), ("x2", 1)],
                memory: vec![],
            },
        ),
(
            "add w0, w1, w2",
            vec![0x20, 0x00, 0x02, 0x0b],
            Arm64Fixture {
                registers: vec![("w1", 0x7fff_ffff), ("w2", 1)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
