use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn fccmp_semantics_match_unicorn_transitions() {
    let cases = [
(
            "fccmp d0, d1, #0, eq",
            vec![0x00, 0x04, 0x61, 0x1e],
            Arm64Fixture {
                registers: vec![
                    ("n", 0),
                    ("z", 1),
                    ("c", 0),
                    ("v", 0),
                    ("d0", 0x4008_0000_0000_0000),
                    ("d1", 0x4014_0000_0000_0000),
                ],
                memory: vec![],
            },
        ),
(
            "fccmp d0, d1, #0, eq",
            vec![0x00, 0x04, 0x61, 0x1e],
            Arm64Fixture {
                registers: vec![
                    ("n", 0),
                    ("z", 0),
                    ("c", 0),
                    ("v", 0),
                    ("d0", 0x4008_0000_0000_0000),
                    ("d1", 0x4014_0000_0000_0000),
                ],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
