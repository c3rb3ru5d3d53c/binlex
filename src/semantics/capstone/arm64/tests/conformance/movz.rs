use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn movz_semantics_match_unicorn_transitions() {
    let cases = [
(
            "movz x0, #0x1234, lsl #16",
            vec![0x80, 0x46, 0xa2, 0xd2],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
(
            "movz x0, #0x1234, lsl #48",
            vec![0x80, 0x46, 0xe2, 0xd2],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
(
            "movz w0, #0x1234, lsl #16",
            vec![0x80, 0x46, 0xa2, 0x52],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
(
            "movz x0, #0x1234, lsl #32",
            vec![0x80, 0x46, 0xc2, 0xd2],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
