use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn cinc_semantics_match_unicorn_transitions() {
    let cases = [
(
            "cinc x0, x1, eq",
            vec![0x20, 0x14, 0x81, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("z", 1)],
                memory: vec![],
            },
        ),
(
            "cinc w0, w1, eq",
            vec![0x20, 0x14, 0x81, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("z", 1)],
                memory: vec![],
            },
        ),
(
            "cinc x0, x1, ne",
            vec![0x20, 0x04, 0x81, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("z", 0)],
                memory: vec![],
            },
        ),
(
            "cinc w0, w1, ne",
            vec![0x20, 0x04, 0x81, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("z", 0)],
                memory: vec![],
            },
        ),
(
            "cinc x0, x1, gt",
            vec![0x20, 0xd4, 0x81, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("z", 0), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
(
            "cinc w0, w1, gt",
            vec![0x20, 0xd4, 0x81, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("z", 0), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
(
            "cinc x0, x1, hi",
            vec![0x20, 0x94, 0x81, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
(
            "cinc w0, w1, hi",
            vec![0x20, 0x94, 0x81, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
(
            "cinc x0, x1, vs",
            vec![0x20, 0x74, 0x81, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("v", 1)],
                memory: vec![],
            },
        ),
(
            "cinc w0, w1, vs",
            vec![0x20, 0x74, 0x81, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("v", 1)],
                memory: vec![],
            },
        ),
(
            "cinc x0, x1, ge",
            vec![0x20, 0xb4, 0x81, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
(
            "cinc w0, w1, ge",
            vec![0x20, 0xb4, 0x81, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
(
            "cinc x0, x1, hs",
            vec![0x20, 0x34, 0x81, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("c", 1)],
                memory: vec![],
            },
        ),
(
            "cinc w0, w1, hs",
            vec![0x20, 0x34, 0x81, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("c", 1)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
