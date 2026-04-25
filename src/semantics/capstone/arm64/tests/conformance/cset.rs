use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn cset_semantics_match_unicorn_transitions() {
    let cases = [
(
            "cset x0, eq",
            vec![0xe0, 0x17, 0x9f, 0x9a],
            Arm64Fixture {
                registers: vec![("z", 1)],
                memory: vec![],
            },
        ),
(
            "cset w0, eq",
            vec![0xe0, 0x17, 0x9f, 0x1a],
            Arm64Fixture {
                registers: vec![("z", 1)],
                memory: vec![],
            },
        ),
(
            "cset x0, ne",
            vec![0xe0, 0x07, 0x9f, 0x9a],
            Arm64Fixture {
                registers: vec![("z", 0)],
                memory: vec![],
            },
        ),
(
            "cset w0, ne",
            vec![0xe0, 0x07, 0x9f, 0x1a],
            Arm64Fixture {
                registers: vec![("z", 0)],
                memory: vec![],
            },
        ),
(
            "cset x0, le",
            vec![0xe0, 0xc7, 0x9f, 0x9a],
            Arm64Fixture {
                registers: vec![("z", 1), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
(
            "cset w0, le",
            vec![0xe0, 0xc7, 0x9f, 0x1a],
            Arm64Fixture {
                registers: vec![("z", 1), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
(
            "cset x0, lt",
            vec![0xe0, 0xa7, 0x9f, 0x9a],
            Arm64Fixture {
                registers: vec![("n", 1), ("v", 0)],
                memory: vec![],
            },
        ),
(
            "cset w0, lt",
            vec![0xe0, 0xa7, 0x9f, 0x1a],
            Arm64Fixture {
                registers: vec![("n", 1), ("v", 0)],
                memory: vec![],
            },
        ),
(
            "cset x0, ls",
            vec![0xe0, 0x87, 0x9f, 0x9a],
            Arm64Fixture {
                registers: vec![("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
(
            "cset w0, ls",
            vec![0xe0, 0x87, 0x9f, 0x1a],
            Arm64Fixture {
                registers: vec![("c", 0), ("z", 0)],
                memory: vec![],
            },
        ),
(
            "cset x0, vc",
            vec![0xe0, 0x67, 0x9f, 0x9a],
            Arm64Fixture {
                registers: vec![("v", 0)],
                memory: vec![],
            },
        ),
(
            "cset w0, vc",
            vec![0xe0, 0x67, 0x9f, 0x1a],
            Arm64Fixture {
                registers: vec![("v", 0)],
                memory: vec![],
            },
        ),
(
            "cset x0, lo",
            vec![0xe0, 0x27, 0x9f, 0x9a],
            Arm64Fixture {
                registers: vec![("c", 0)],
                memory: vec![],
            },
        ),
(
            "cset w0, lo",
            vec![0xe0, 0x27, 0x9f, 0x1a],
            Arm64Fixture {
                registers: vec![("c", 0)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
