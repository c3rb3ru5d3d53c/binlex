use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn mov_semantics_match_unicorn_transitions() {
    let cases = [
(
            "mov x0, x1",
            vec![0xe0, 0x03, 0x01, 0xaa],
            Arm64Fixture {
                registers: vec![("x1", 0x1234_5678_9abc_def0)],
                memory: vec![],
            },
        ),
(
            "mov w0, #0x1234",
            vec![0x80, 0x46, 0x82, 0x52],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
(
            "mov w0, #-4661",
            vec![0x80, 0x46, 0x82, 0x12],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
(
            "mov w0, w1",
            vec![0xe0, 0x03, 0x01, 0x2a],
            Arm64Fixture {
                registers: vec![("w1", 0x1234_5678)],
                memory: vec![],
            },
        ),
(
            "mov x0, #0x1234",
            vec![0x80, 0x46, 0x82, 0xd2],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
(
            "mov x0, #-4661",
            vec![0x80, 0x46, 0x82, 0x92],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
(
            "mov w0, #0x1234",
            vec![0x80, 0x46, 0x82, 0x52],
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
