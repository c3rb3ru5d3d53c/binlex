use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn csinc_semantics_match_unicorn_transitions() {
    let cases = [
(
            "csinc x0, x1, x2, eq",
            vec![0x20, 0x04, 0x82, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("x2", 0x20), ("z", 0)],
                memory: vec![],
            },
        ),
(
            "csinc w0, w1, w2, eq",
            vec![0x20, 0x04, 0x82, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("w2", 0x20), ("z", 0)],
                memory: vec![],
            },
        ),
(
            "csinc x0, x1, x2, mi",
            vec![0x20, 0x44, 0x82, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("x2", 0x20), ("n", 1)],
                memory: vec![],
            },
        ),
(
            "csinc w0, w1, w2, mi",
            vec![0x20, 0x44, 0x82, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("w2", 0x20), ("n", 1)],
                memory: vec![],
            },
        ),
(
            "csinc x0, x1, x2, gt",
            vec![0x20, 0xc4, 0x82, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("x2", 0x20), ("z", 0), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
(
            "csinc w0, w1, w2, gt",
            vec![0x20, 0xc4, 0x82, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("w2", 0x20), ("z", 0), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
(
            "csinc x0, x1, x2, ge",
            vec![0x20, 0xa4, 0x82, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("x2", 0x20), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
(
            "csinc w0, w1, w2, ge",
            vec![0x20, 0xa4, 0x82, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("w2", 0x20), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
(
            "csinc x0, x1, x2, hi",
            vec![0x20, 0x84, 0x82, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("x2", 0x20), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
(
            "csinc w0, w1, w2, hi",
            vec![0x20, 0x84, 0x82, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("w2", 0x20), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
(
            "csinc x0, x1, x2, vs",
            vec![0x20, 0x64, 0x82, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("x2", 0x20), ("v", 1)],
                memory: vec![],
            },
        ),
(
            "csinc w0, w1, w2, vs",
            vec![0x20, 0x64, 0x82, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("w2", 0x20), ("v", 1)],
                memory: vec![],
            },
        ),
(
            "csinc x0, x1, x2, hs",
            vec![0x20, 0x24, 0x82, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("x2", 0x20), ("c", 1)],
                memory: vec![],
            },
        ),
(
            "csinc w0, w1, w2, hs",
            vec![0x20, 0x24, 0x82, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("w2", 0x20), ("c", 1)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
