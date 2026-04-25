use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn fcmpe_semantics_match_unicorn_transitions() {
    let cases = [
(
            "fcmpe d0, d1",
            vec![0x00, 0x20, 0x61, 0x1e],
            Arm64Fixture {
                registers: vec![
                    ("n", 0),
                    ("z", 1),
                    ("c", 0),
                    ("v", 0),
                    ("d0", 0x4014_0000_0000_0000),
                    ("d1", 0x4008_0000_0000_0000),
                ],
                memory: vec![],
            },
        ),
(
            "fcmpe s0, s1",
            vec![0x10, 0x20, 0x21, 0x1e],
            Arm64Fixture {
                registers: vec![
                    ("n", 0),
                    ("z", 1),
                    ("c", 0),
                    ("v", 0),
                    ("s0", 0x4080_0000),
                    ("s1", 0x4040_0000),
                ],
                memory: vec![],
            },
        ),
(
            "fcmpe d0, #0.0",
            vec![0x18, 0x20, 0x60, 0x1e],
            Arm64Fixture {
                registers: vec![
                    ("n", 0),
                    ("z", 1),
                    ("c", 0),
                    ("v", 0),
                    ("d0", 0x4008_0000_0000_0000),
                ],
                memory: vec![],
            },
        ),
(
            "fcmpe s0, #0.0",
            vec![0x18, 0x20, 0x20, 0x1e],
            Arm64Fixture {
                registers: vec![
                    ("n", 0),
                    ("z", 1),
                    ("c", 0),
                    ("v", 0),
                    ("s0", 0x4040_0000),
                ],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
