use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn atomic_semantics_match_unicorn_transitions() {
    let cases = [
        (
            "stlrh w0, [x1]",
            vec![0x20, 0xfc, 0x9f, 0x48],
            Arm64Fixture {
                registers: vec![("w0", 0x1234_abcd), ("x1", 0x2000)],
                memory: vec![(0x2000, vec![0x00, 0x00])],
            },
        ),
        (
            "ldar x0, [x1]",
            vec![0x20, 0xfc, 0xdf, 0xc8],
            Arm64Fixture {
                registers: vec![("x1", 0x3000)],
                memory: vec![(0x3000, vec![0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11])],
            },
        ),
        (
            "ldarb w0, [x1]",
            vec![0x20, 0xfc, 0xdf, 0x08],
            Arm64Fixture {
                registers: vec![("x1", 0x2000)],
                memory: vec![(0x2000, vec![0xab])],
            },
        ),
        (
            "ldarh w0, [x1]",
            vec![0x20, 0xfc, 0xdf, 0x48],
            Arm64Fixture {
                registers: vec![("x1", 0x2000)],
                memory: vec![(0x2000, vec![0xcd, 0xab])],
            },
        ),
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
