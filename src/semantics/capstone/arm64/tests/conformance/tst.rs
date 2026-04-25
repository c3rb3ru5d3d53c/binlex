use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn tst_semantics_match_unicorn_transitions() {
    let cases = [
(
            "tst x0, x1",
            vec![0x1f, 0x00, 0x01, 0xea],
            Arm64Fixture {
                registers: vec![
                    ("x0", 0xf0f0_0000_f0f0_0000),
                    ("x1", 0x0ff0_0ff0_0ff0_0ff0),
                    ("n", 0),
                    ("z", 0),
                    ("c", 0),
                    ("v", 0),
                ],
                memory: vec![],
            },
        ),
(
            "tst w0, w1",
            vec![0x1f, 0x00, 0x01, 0x6a],
            Arm64Fixture {
                registers: vec![
                    ("w0", 0xf0f0_0000),
                    ("w1", 0x0ff0_0ff0),
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
