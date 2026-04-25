use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn csetm_semantics_match_unicorn_transitions() {
    let cases = [
(
            "csetm x0, eq",
            vec![0xe0, 0x13, 0x9f, 0xda],
            Arm64Fixture {
                registers: vec![("z", 1)],
                memory: vec![],
            },
        ),
(
            "csetm w0, eq",
            vec![0xe0, 0x13, 0x9f, 0x5a],
            Arm64Fixture {
                registers: vec![("z", 1)],
                memory: vec![],
            },
        ),
(
            "csetm x0, ne",
            vec![0xe0, 0x03, 0x9f, 0xda],
            Arm64Fixture {
                registers: vec![("z", 0)],
                memory: vec![],
            },
        ),
(
            "csetm w0, ne",
            vec![0xe0, 0x03, 0x9f, 0x5a],
            Arm64Fixture {
                registers: vec![("z", 0)],
                memory: vec![],
            },
        ),
(
            "csetm x0, gt",
            vec![0xe0, 0xd3, 0x9f, 0xda],
            Arm64Fixture {
                registers: vec![("z", 0), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
(
            "csetm w0, gt",
            vec![0xe0, 0xd3, 0x9f, 0x5a],
            Arm64Fixture {
                registers: vec![("z", 0), ("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
(
            "csetm x0, hi",
            vec![0xe0, 0x93, 0x9f, 0xda],
            Arm64Fixture {
                registers: vec![("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
(
            "csetm w0, hi",
            vec![0xe0, 0x93, 0x9f, 0x5a],
            Arm64Fixture {
                registers: vec![("c", 1), ("z", 0)],
                memory: vec![],
            },
        ),
(
            "csetm x0, vs",
            vec![0xe0, 0x73, 0x9f, 0xda],
            Arm64Fixture {
                registers: vec![("v", 1)],
                memory: vec![],
            },
        ),
(
            "csetm w0, vs",
            vec![0xe0, 0x73, 0x9f, 0x5a],
            Arm64Fixture {
                registers: vec![("v", 1)],
                memory: vec![],
            },
        ),
(
            "csetm x0, ge",
            vec![0xe0, 0xb3, 0x9f, 0xda],
            Arm64Fixture {
                registers: vec![("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
(
            "csetm w0, ge",
            vec![0xe0, 0xb3, 0x9f, 0x5a],
            Arm64Fixture {
                registers: vec![("n", 0), ("v", 0)],
                memory: vec![],
            },
        ),
(
            "csetm x0, hs",
            vec![0xe0, 0x33, 0x9f, 0xda],
            Arm64Fixture {
                registers: vec![("c", 1)],
                memory: vec![],
            },
        ),
(
            "csetm w0, hs",
            vec![0xe0, 0x33, 0x9f, 0x5a],
            Arm64Fixture {
                registers: vec![("c", 1)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
