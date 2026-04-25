use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn tbnz_semantics_match_unicorn_transitions() {
    let cases = [
(
            "tbnz w0, #3, #0x10",
            vec![0x80, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w0", 8)],
                memory: vec![],
            },
        ),
(
            "tbnz w0, #3, #0x10",
            vec![0x80, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w0", 0)],
                memory: vec![],
            },
        ),
(
            "tbnz w1, #3, #0x10",
            vec![0x81, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w1", 8)],
                memory: vec![],
            },
        ),
(
            "tbnz w1, #3, #0x10",
            vec![0x81, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w1", 0)],
                memory: vec![],
            },
        ),
(
            "tbnz x1, #35, #0x10",
            vec![0x81, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x1", 0x0000_0008_0000_0000)],
                memory: vec![],
            },
        ),
(
            "tbnz x1, #35, #0x10",
            vec![0x81, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x1", 0)],
                memory: vec![],
            },
        ),
(
            "tbnz w2, #3, #0x10",
            vec![0x82, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w2", 8)],
                memory: vec![],
            },
        ),
(
            "tbnz w2, #3, #0x10",
            vec![0x82, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w2", 0)],
                memory: vec![],
            },
        ),
(
            "tbnz x2, #35, #0x10",
            vec![0x82, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x2", 0x0000_0008_0000_0000)],
                memory: vec![],
            },
        ),
(
            "tbnz x2, #35, #0x10",
            vec![0x82, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x2", 0)],
                memory: vec![],
            },
        ),
(
            "tbnz w3, #3, #0x10",
            vec![0x83, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w3", 8)],
                memory: vec![],
            },
        ),
(
            "tbnz w3, #3, #0x10",
            vec![0x83, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w3", 0)],
                memory: vec![],
            },
        ),
(
            "tbnz x3, #35, #0x10",
            vec![0x83, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x3", 0x0000_0008_0000_0000)],
                memory: vec![],
            },
        ),
(
            "tbnz x3, #35, #0x10",
            vec![0x83, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x3", 0)],
                memory: vec![],
            },
        ),
(
            "tbnz w4, #3, #0x10",
            vec![0x84, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w4", 8)],
                memory: vec![],
            },
        ),
(
            "tbnz w4, #3, #0x10",
            vec![0x84, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w4", 0)],
                memory: vec![],
            },
        ),
(
            "tbnz x4, #35, #0x10",
            vec![0x84, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x4", 0x0000_0008_0000_0000)],
                memory: vec![],
            },
        ),
(
            "tbnz x4, #35, #0x10",
            vec![0x84, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x4", 0)],
                memory: vec![],
            },
        ),
(
            "tbnz w5, #3, #0x10",
            vec![0x85, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w5", 8)],
                memory: vec![],
            },
        ),
(
            "tbnz w5, #3, #0x10",
            vec![0x85, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w5", 0)],
                memory: vec![],
            },
        ),
(
            "tbnz x5, #35, #0x10",
            vec![0x85, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x5", 0x0000_0008_0000_0000)],
                memory: vec![],
            },
        ),
(
            "tbnz x5, #35, #0x10",
            vec![0x85, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x5", 0)],
                memory: vec![],
            },
        ),
(
            "tbnz w6, #3, #0x10",
            vec![0x86, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w6", 8)],
                memory: vec![],
            },
        ),
(
            "tbnz w6, #3, #0x10",
            vec![0x86, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w6", 0)],
                memory: vec![],
            },
        ),
(
            "tbnz x6, #35, #0x10",
            vec![0x86, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x6", 0x0000_0008_0000_0000)],
                memory: vec![],
            },
        ),
(
            "tbnz x6, #35, #0x10",
            vec![0x86, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x6", 0)],
                memory: vec![],
            },
        ),
(
            "tbnz w7, #3, #0x10",
            vec![0x87, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w7", 8)],
                memory: vec![],
            },
        ),
(
            "tbnz w7, #3, #0x10",
            vec![0x87, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w7", 0)],
                memory: vec![],
            },
        ),
(
            "tbnz x7, #35, #0x10",
            vec![0x87, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x7", 0x0000_0008_0000_0000)],
                memory: vec![],
            },
        ),
(
            "tbnz x7, #35, #0x10",
            vec![0x87, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x7", 0)],
                memory: vec![],
            },
        ),
(
            "tbnz w8, #3, #0x10",
            vec![0x88, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w8", 8)],
                memory: vec![],
            },
        ),
(
            "tbnz w8, #3, #0x10",
            vec![0x88, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w8", 0)],
                memory: vec![],
            },
        ),
(
            "tbnz x8, #35, #0x10",
            vec![0x88, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x8", 0x0000_0008_0000_0000)],
                memory: vec![],
            },
        ),
(
            "tbnz x8, #35, #0x10",
            vec![0x88, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x8", 0)],
                memory: vec![],
            },
        ),
(
            "tbnz w9, #3, #0x10",
            vec![0x89, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w9", 8)],
                memory: vec![],
            },
        ),
(
            "tbnz w9, #3, #0x10",
            vec![0x89, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w9", 0)],
                memory: vec![],
            },
        ),
(
            "tbnz x9, #35, #0x10",
            vec![0x89, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x9", 0x0000_0008_0000_0000)],
                memory: vec![],
            },
        ),
(
            "tbnz x9, #35, #0x10",
            vec![0x89, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x9", 0)],
                memory: vec![],
            },
        ),
(
            "tbnz w10, #3, #0x10",
            vec![0x8a, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w10", 8)],
                memory: vec![],
            },
        ),
(
            "tbnz w10, #3, #0x10",
            vec![0x8a, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w10", 0)],
                memory: vec![],
            },
        ),
(
            "tbnz x10, #35, #0x10",
            vec![0x8a, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x10", 0x0000_0008_0000_0000)],
                memory: vec![],
            },
        ),
(
            "tbnz x10, #35, #0x10",
            vec![0x8a, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x10", 0)],
                memory: vec![],
            },
        ),
(
            "tbnz w11, #3, #0x10",
            vec![0x8b, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w11", 8)],
                memory: vec![],
            },
        ),
(
            "tbnz w11, #3, #0x10",
            vec![0x8b, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w11", 0)],
                memory: vec![],
            },
        ),
(
            "tbnz x11, #35, #0x10",
            vec![0x8b, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x11", 0x0000_0008_0000_0000)],
                memory: vec![],
            },
        ),
(
            "tbnz x11, #35, #0x10",
            vec![0x8b, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x11", 0)],
                memory: vec![],
            },
        ),
(
            "tbnz w12, #3, #0x10",
            vec![0x8c, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w12", 8)],
                memory: vec![],
            },
        ),
(
            "tbnz w12, #3, #0x10",
            vec![0x8c, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w12", 0)],
                memory: vec![],
            },
        ),
(
            "tbnz x12, #35, #0x10",
            vec![0x8c, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x12", 0x0000_0008_0000_0000)],
                memory: vec![],
            },
        ),
(
            "tbnz x12, #35, #0x10",
            vec![0x8c, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x12", 0)],
                memory: vec![],
            },
        ),
(
            "tbnz w13, #3, #0x10",
            vec![0x8d, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w13", 8)],
                memory: vec![],
            },
        ),
(
            "tbnz w13, #3, #0x10",
            vec![0x8d, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w13", 0)],
                memory: vec![],
            },
        ),
(
            "tbnz x13, #35, #0x10",
            vec![0x8d, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x13", 0x0000_0008_0000_0000)],
                memory: vec![],
            },
        ),
(
            "tbnz x13, #35, #0x10",
            vec![0x8d, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x13", 0)],
                memory: vec![],
            },
        ),
(
            "tbnz w14, #3, #0x10",
            vec![0x8e, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w14", 8)],
                memory: vec![],
            },
        ),
(
            "tbnz w14, #3, #0x10",
            vec![0x8e, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w14", 0)],
                memory: vec![],
            },
        ),
(
            "tbnz x14, #35, #0x10",
            vec![0x8e, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x14", 0x0000_0008_0000_0000)],
                memory: vec![],
            },
        ),
(
            "tbnz x14, #35, #0x10",
            vec![0x8e, 0x00, 0x18, 0xb7],
            Arm64Fixture {
                registers: vec![("x14", 0)],
                memory: vec![],
            },
        ),
(
            "tbnz w15, #3, #0x10",
            vec![0x8f, 0x00, 0x18, 0x37],
            Arm64Fixture {
                registers: vec![("w15", 8)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
