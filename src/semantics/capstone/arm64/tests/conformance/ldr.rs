use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn ldr_semantics_match_unicorn_transitions() {
    let cases = [
(
            "ldr x0, [x1, x2]",
            vec![0x20, 0x68, 0x62, 0xf8],
            Arm64Fixture {
                registers: vec![("x1", 0x3000), ("x2", 0x10)],
                memory: vec![(0x3010, vec![0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11])],
            },
        ),
(
            "ldr w0, [x1, x2]",
            vec![0x20, 0x68, 0x62, 0xb8],
            Arm64Fixture {
                registers: vec![("x1", 0x3000), ("x2", 0x10)],
                memory: vec![(0x3010, vec![0x78, 0x56, 0x34, 0x12])],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
