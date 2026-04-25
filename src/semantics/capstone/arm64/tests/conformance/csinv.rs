use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn csinv_semantics_match_unicorn_transitions() {
    let cases = [
(
            "csinv x0, x1, x2, eq",
            vec![0x20, 0x00, 0x82, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("x2", 0x0f), ("z", 0)],
                memory: vec![],
            },
        ),
(
            "csinv w0, w1, w2, eq",
            vec![0x20, 0x00, 0x82, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("w2", 0x0f), ("z", 0)],
                memory: vec![],
            },
        ),
(
            "csinv x0, x1, x2, pl",
            vec![0x20, 0x50, 0x82, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("x2", 0x0f), ("n", 0)],
                memory: vec![],
            },
        ),
(
            "csinv w0, w1, w2, pl",
            vec![0x20, 0x50, 0x82, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("w2", 0x0f), ("n", 0)],
                memory: vec![],
            },
        ),
(
            "csinv x0, x1, x2, le",
            vec![0x20, 0xd0, 0x82, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("x2", 0x0f), ("z", 1), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
(
            "csinv w0, w1, w2, le",
            vec![0x20, 0xd0, 0x82, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("w2", 0x0f), ("z", 1), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
(
            "csinv x0, x1, x2, lt",
            vec![0x20, 0xb0, 0x82, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("x2", 0x0f), ("n", 1), ("v", 0)],
                memory: vec![],
            },
        ),
(
            "csinv w0, w1, w2, lt",
            vec![0x20, 0xb0, 0x82, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("w2", 0x0f), ("n", 1), ("v", 0)],
                memory: vec![],
            },
        ),
(
            "csinv x0, x1, x2, ls",
            vec![0x20, 0x90, 0x82, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("x2", 0x0f), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
(
            "csinv w0, w1, w2, ls",
            vec![0x20, 0x90, 0x82, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("w2", 0x0f), ("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
(
            "csinv x0, x1, x2, vc",
            vec![0x20, 0x70, 0x82, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("x2", 0x0f), ("v", 0)],
                memory: vec![],
            },
        ),
(
            "csinv w0, w1, w2, vc",
            vec![0x20, 0x70, 0x82, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("w2", 0x0f), ("v", 0)],
                memory: vec![],
            },
        ),
(
            "csinv x0, x1, x2, lo",
            vec![0x20, 0x30, 0x82, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 0x10), ("x2", 0x0f), ("c", 0)],
                memory: vec![],
            },
        ),
(
            "csinv w0, w1, w2, lo",
            vec![0x20, 0x30, 0x82, 0x5a],
            Arm64Fixture {
                registers: vec![("w1", 0x10), ("w2", 0x0f), ("c", 0)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
