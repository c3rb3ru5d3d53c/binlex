use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn ldp_semantics_match_unicorn_transitions() {
    let cases = [
(
            "ldp x0, x1, [x2]",
            vec![0x40, 0x04, 0x40, 0xa9],
            Arm64Fixture {
                registers: vec![("x2", 0x3000)],
                memory: vec![(
                    0x3000,
                    vec![
                        0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x18, 0x17, 0x16, 0x15,
                        0x14, 0x13, 0x12, 0x11,
                    ],
                )],
            },
        ),
(
            "ldp x0, x1, [x2], #16",
            vec![0x40, 0x04, 0xc1, 0xa8],
            Arm64Fixture {
                registers: vec![("x2", 0x3000)],
                memory: vec![(
                    0x3000,
                    vec![
                        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
                        0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99,
                    ],
                )],
            },
        ),
(
            "ldp x0, x1, [sp], #16",
            vec![0xe0, 0x07, 0xc1, 0xa8],
            Arm64Fixture {
                registers: vec![("sp", 0x2fe0)],
                memory: vec![(
                    0x2fe0,
                    vec![
                        0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
                        0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11,
                    ],
                )],
            },
        ),
(
            "ldp x0, x1, [sp, #-16]!",
            vec![0xe0, 0x07, 0xff, 0xa9],
            Arm64Fixture {
                registers: vec![("sp", 0x2ff0)],
                memory: vec![(
                    0x2fe0,
                    vec![
                        0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
                        0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11,
                    ],
                )],
            },
        ),
(
            "ldp w0, w1, [x2]",
            vec![0x40, 0x04, 0x40, 0x29],
            Arm64Fixture {
                registers: vec![("x2", 0x3000)],
                memory: vec![(
                    0x3000,
                    vec![0x78, 0x56, 0x34, 0x12, 0xef, 0xcd, 0xab, 0x89],
                )],
            },
        ),
(
            "ldp w0, w1, [x2], #8",
            vec![0x40, 0x04, 0xc1, 0x28],
            Arm64Fixture {
                registers: vec![("x2", 0x3000)],
                memory: vec![(
                    0x3000,
                    vec![0x78, 0x56, 0x34, 0x12, 0xef, 0xcd, 0xab, 0x89],
                )],
            },
        ),
(
            "ldp w0, w1, [sp], #8",
            vec![0xe0, 0x07, 0xc1, 0x28],
            Arm64Fixture {
                registers: vec![("sp", 0x2fe8)],
                memory: vec![(
                    0x2fe8,
                    vec![0x78, 0x56, 0x34, 0x12, 0xef, 0xcd, 0xab, 0x89],
                )],
            },
        ),
(
            "ldp w0, w1, [sp, #-8]!",
            vec![0xe0, 0x07, 0xff, 0x29],
            Arm64Fixture {
                registers: vec![("sp", 0x2ff0)],
                memory: vec![(
                    0x2fe8,
                    vec![0x78, 0x56, 0x34, 0x12, 0xef, 0xcd, 0xab, 0x89],
                )],
            },
        ),
(
            "ldp x29, x30, [sp], #16",
            vec![0xfd, 0x7b, 0xc1, 0xa8],
            Arm64Fixture {
                registers: vec![("sp", 0x2fe0)],
                memory: vec![(
                    0x2fe0,
                    vec![
                        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
                        0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99,
                    ],
                )],
            },
        ),
(
            "ldp x29, x30, [sp]",
            vec![0xfd, 0x7b, 0x40, 0xa9],
            Arm64Fixture {
                registers: vec![("sp", 0x2fe0)],
                memory: vec![(
                    0x2fe0,
                    vec![
                        0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
                        0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11,
                    ],
                )],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
