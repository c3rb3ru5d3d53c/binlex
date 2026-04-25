use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn cneg_semantics_match_unicorn_transitions() {
    let cases = [
(
            "cneg x0, x1, eq",
            vec![0x20, 0x14, 0x81, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 5), ("z", 1)],
                memory: vec![],
            },
        ),
(
            "cneg w0, w1, eq",
            vec![0x20, 0x14, 0x81, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 5), ("z", 1)],
                memory: vec![],
            },
        ),
(
            "cneg x0, x1, mi",
            vec![0x20, 0x54, 0x81, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 5), ("n", 1)],
                memory: vec![],
            },
        ),
(
            "cneg w0, w1, mi",
            vec![0x20, 0x54, 0x81, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 5), ("n", 1)],
                memory: vec![],
            },
        ),
(
            "cneg x0, x1, le",
            vec![0x20, 0xc4, 0x81, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 5), ("z", 1), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
(
            "cneg w0, w1, le",
            vec![0x20, 0xc4, 0x81, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 5), ("z", 1), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
(
            "cneg x0, x1, ls",
            vec![0x20, 0x84, 0x81, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 5), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
(
            "cneg w0, w1, ls",
            vec![0x20, 0x84, 0x81, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 5), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
(
            "cneg x0, x1, vc",
            vec![0x20, 0x64, 0x81, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 5), ("v", 0)],
                memory: vec![],
            },
        ),
(
            "cneg w0, w1, vc",
            vec![0x20, 0x64, 0x81, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 5), ("v", 0)],
                memory: vec![],
            },
        ),
(
            "cneg x0, x1, lt",
            vec![0x20, 0xa4, 0x81, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 5), ("n", 1), ("v", 0)],
                memory: vec![],
            },
        ),
(
            "cneg w0, w1, lt",
            vec![0x20, 0xa4, 0x81, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 5), ("n", 1), ("v", 0)],
                memory: vec![],
            },
        ),
(
            "cneg x0, x1, lo",
            vec![0x20, 0x24, 0x81, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 5), ("c", 0)],
                memory: vec![],
            },
        ),
(
            "cneg w0, w1, lo",
            vec![0x20, 0x24, 0x81, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 5), ("c", 0)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
