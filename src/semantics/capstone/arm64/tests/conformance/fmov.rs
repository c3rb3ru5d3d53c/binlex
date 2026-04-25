use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn fmov_semantics_match_unicorn_transitions() {
    let cases = [
(
            "fmov d0, d1",
            vec![0x20, 0x40, 0x60, 0x1e],
            Arm64Fixture {
                registers: vec![("d1", 0x4008_0000_0000_0000)],
                memory: vec![],
            },
        ),
(
            "fmov d1, x0",
            vec![0x01, 0x00, 0x67, 0x9e],
            Arm64Fixture {
                registers: vec![("x0", 0x4008_0000_0000_0000)],
                memory: vec![],
            },
        ),
(
            "fmov s0, w1",
            vec![0x20, 0x00, 0x27, 0x1e],
            Arm64Fixture {
                registers: vec![("w1", 0x4040_0000)],
                memory: vec![],
            },
        ),
(
            "fmov d0, #1.0",
            vec![0x00, 0x10, 0x6e, 0x1e],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
(
            "fmov s0, #1.0",
            vec![0x00, 0x10, 0x2e, 0x1e],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
(
            "fmov x0, d1",
            vec![0x20, 0x00, 0x66, 0x9e],
            Arm64Fixture {
                registers: vec![("d1", 0x4008_0000_0000_0000)],
                memory: vec![],
            },
        ),
(
            "fmov x1, d0",
            vec![0x01, 0x00, 0x66, 0x9e],
            Arm64Fixture {
                registers: vec![("d0", 0x4008_0000_0000_0000)],
                memory: vec![],
            },
        ),
(
            "fmov w0, s1",
            vec![0x20, 0x00, 0x26, 0x1e],
            Arm64Fixture {
                registers: vec![("s1", 0x4040_0000)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
