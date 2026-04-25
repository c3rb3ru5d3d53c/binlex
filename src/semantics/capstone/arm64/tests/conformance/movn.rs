use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn movn_semantics_match_unicorn_transitions() {
    let cases = [
(
            "movn x0, #0x1234, lsl #16",
            vec![0x80, 0x46, 0xa2, 0x92],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
(
            "movn x0, #0x1234",
            vec![0x80, 0x46, 0x82, 0x92],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
(
            "movn w0, #0x1234",
            vec![0x80, 0x46, 0x82, 0x12],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
(
            "movn w0, #0x1234, lsl #16",
            vec![0x80, 0x46, 0xa2, 0x12],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
(
            "movn x0, #0x1234, lsl #32",
            vec![0x80, 0x46, 0xc2, 0x92],
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
