use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn csneg_semantics_match_unicorn_transitions() {
    let cases = [
(
            "csneg x0, x1, x2, eq",
            vec![0x20, 0x04, 0x82, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("x2", 5), ("z", 0)],
                memory: vec![],
            },
        ),
(
            "csneg w0, w1, w2, eq",
            vec![0x20, 0x04, 0x82, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("w2", 5), ("z", 0)],
                memory: vec![],
            },
        ),
(
            "csneg x0, x1, x2, mi",
            vec![0x20, 0x44, 0x82, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("x2", 5), ("n", 1)],
                memory: vec![],
            },
        ),
(
            "csneg w0, w1, w2, mi",
            vec![0x20, 0x44, 0x82, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("w2", 5), ("n", 1)],
                memory: vec![],
            },
        ),
(
            "csneg x0, x1, x2, le",
            vec![0x20, 0xd4, 0x82, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("x2", 5), ("z", 1), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
(
            "csneg w0, w1, w2, le",
            vec![0x20, 0xd4, 0x82, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("w2", 5), ("z", 1), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
(
            "csneg x0, x1, x2, ls",
            vec![0x20, 0x94, 0x82, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("x2", 5), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
(
            "csneg w0, w1, w2, ls",
            vec![0x20, 0x94, 0x82, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("w2", 5), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
(
            "csneg x0, x1, x2, vc",
            vec![0x20, 0x74, 0x82, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("x2", 5), ("v", 0)],
                memory: vec![],
            },
        ),
(
            "csneg w0, w1, w2, vc",
            vec![0x20, 0x74, 0x82, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("w2", 5), ("v", 0)],
                memory: vec![],
            },
        ),
(
            "csneg x0, x1, x2, lt",
            vec![0x20, 0xb4, 0x82, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("x2", 5), ("n", 1), ("v", 0)],
                memory: vec![],
            },
        ),
(
            "csneg w0, w1, w2, lt",
            vec![0x20, 0xb4, 0x82, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("w2", 5), ("n", 1), ("v", 0)],
                memory: vec![],
            },
        ),
(
            "csneg x0, x1, x2, lo",
            vec![0x20, 0x34, 0x82, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("x2", 5), ("c", 0)],
                memory: vec![],
            },
        ),
(
            "csneg w0, w1, w2, lo",
            vec![0x20, 0x34, 0x82, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("w2", 5), ("c", 0)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
