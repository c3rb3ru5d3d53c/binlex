use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn movk_semantics_match_unicorn_transitions() {
    let cases = [
(
            "movk x0, #0x1234, lsl #16",
            vec![0x80, 0x46, 0xa2, 0xf2],
            Arm64Fixture {
                registers: vec![("x0", 0xffff_ffff_0000_ffff)],
                memory: vec![],
            },
        ),
(
            "movk w0, #0x1234, lsl #16",
            vec![0x80, 0x46, 0xa2, 0x72],
            Arm64Fixture {
                registers: vec![("w0", 0x0000_ffff)],
                memory: vec![],
            },
        ),
(
            "movk x0, #0x1234",
            vec![0x80, 0x46, 0x82, 0xf2],
            Arm64Fixture {
                registers: vec![("x0", 0xffff_ffff_0000_ffff)],
                memory: vec![],
            },
        ),
(
            "movk w0, #0x1234",
            vec![0x80, 0x46, 0x82, 0x72],
            Arm64Fixture {
                registers: vec![("w0", 0x0000_ffff)],
                memory: vec![],
            },
        ),
(
            "movk x0, #0x1234, lsl #48",
            vec![0x80, 0x46, 0xe2, 0xf2],
            Arm64Fixture {
                registers: vec![("x0", 0x0000_ffff_0000_ffff)],
                memory: vec![],
            },
        ),
(
            "movk x0, #0x1234, lsl #32",
            vec![0x80, 0x46, 0xc2, 0xf2],
            Arm64Fixture {
                registers: vec![("x0", 0x0000_ffff_0000_ffff)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
