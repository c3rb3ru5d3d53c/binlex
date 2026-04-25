use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn csel_semantics_match_unicorn_transitions() {
    let cases = [
(
            "csel x0, x1, x2, eq",
            vec![0x20, 0x00, 0x82, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 0x1111), ("x2", 0x2222), ("z", 1)],
                memory: vec![],
            },
        ),
(
            "csel w0, w1, w2, eq",
            vec![0x20, 0x00, 0x82, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 0x1111), ("w2", 0x2222), ("z", 1)],
                memory: vec![],
            },
        ),
(
            "csel x0, x1, x2, ne",
            vec![0x20, 0x10, 0x82, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 0x1111), ("x2", 0x2222), ("z", 0)],
                memory: vec![],
            },
        ),
(
            "csel w0, w1, w2, ne",
            vec![0x20, 0x10, 0x82, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 0x1111), ("w2", 0x2222), ("z", 0)],
                memory: vec![],
            },
        ),
(
            "csel x0, x1, x2, gt",
            vec![0x20, 0xc0, 0x82, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 0x1111), ("x2", 0x2222), ("z", 0), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
(
            "csel w0, w1, w2, gt",
            vec![0x20, 0xc0, 0x82, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 0x1111), ("w2", 0x2222), ("z", 0), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
(
            "csel x0, x1, x2, ge",
            vec![0x20, 0xa0, 0x82, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 0x1111), ("x2", 0x2222), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
(
            "csel w0, w1, w2, ge",
            vec![0x20, 0xa0, 0x82, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 0x1111), ("w2", 0x2222), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
(
            "csel x0, x1, x2, hi",
            vec![0x20, 0x80, 0x82, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 0x1111), ("x2", 0x2222), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
(
            "csel w0, w1, w2, hi",
            vec![0x20, 0x80, 0x82, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 0x1111), ("w2", 0x2222), ("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
(
            "csel x0, x1, x2, vs",
            vec![0x20, 0x60, 0x82, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 0x1111), ("x2", 0x2222), ("v", 1)],
                memory: vec![],
            },
        ),
(
            "csel w0, w1, w2, vs",
            vec![0x20, 0x60, 0x82, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 0x1111), ("w2", 0x2222), ("v", 1)],
                memory: vec![],
            },
        ),
(
            "csel x0, x1, x2, hs",
            vec![0x20, 0x20, 0x82, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 0x1111), ("x2", 0x2222), ("c", 1)],
                memory: vec![],
            },
        ),
(
            "csel w0, w1, w2, hs",
            vec![0x20, 0x20, 0x82, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 0x1111), ("w2", 0x2222), ("c", 1)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
