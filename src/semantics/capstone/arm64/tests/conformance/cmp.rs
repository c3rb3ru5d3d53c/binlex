use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn cmp_semantics_match_unicorn_transitions() {
    let cases = [
(
            "cmp x0, x1",
            vec![0x1f, 0x00, 0x01, 0xeb],
            Arm64Fixture {
                registers: vec![
                    ("x0", 5),
                    ("x1", 7),
                    ("n", 0),
                    ("z", 0),
                    ("c", 0),
                    ("v", 0),
                ],
                memory: vec![],
            },
        ),
(
            "cmp w0, w1",
            vec![0x1f, 0x00, 0x01, 0x6b],
            Arm64Fixture {
                registers: vec![
                    ("w0", 5),
                    ("w1", 7),
                    ("n", 0),
                    ("z", 0),
                    ("c", 0),
                    ("v", 0),
                ],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
