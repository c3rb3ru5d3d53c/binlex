use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn memory_semantics_match_unicorn_transitions() {
    let cases = [
        (
            "ldrb w0, [x1]",
            vec![0x20, 0x00, 0x40, 0x39],
            Arm64Fixture {
                registers: vec![("x1", 0x2000)],
                memory: vec![(0x2000, vec![0xab])],
            },
        ),
        (
            "strb w0, [x1]",
            vec![0x20, 0x00, 0x00, 0x39],
            Arm64Fixture {
                registers: vec![("w0", 0x1234_56ab), ("x1", 0x2000)],
                memory: vec![(0x2000, vec![0x00])],
            },
        ),
        (
            "ldur x0, [x1, #8]",
            vec![0x20, 0x80, 0x40, 0xf8],
            Arm64Fixture {
                registers: vec![("x1", 0x3000)],
                memory: vec![(0x3008, vec![0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11])],
            },
        ),
        (
            "stur x0, [x1, #8]",
            vec![0x20, 0x80, 0x00, 0xf8],
            Arm64Fixture {
                registers: vec![("x0", 0x1122_3344_5566_7788), ("x1", 0x3000)],
                memory: vec![(0x3008, vec![0; 8])],
            },
        ),
        (
            "ldrh w0, [x1]",
            vec![0x20, 0x00, 0x40, 0x79],
            Arm64Fixture {
                registers: vec![("x1", 0x2000)],
                memory: vec![(0x2000, vec![0xcd, 0xab])],
            },
        ),
        (
            "strh w0, [x1]",
            vec![0x20, 0x00, 0x00, 0x79],
            Arm64Fixture {
                registers: vec![("w0", 0x1234_abcd), ("x1", 0x2000)],
                memory: vec![(0x2000, vec![0x00, 0x00])],
            },
        ),
        (
            "ldurb w0, [x1, #8]",
            vec![0x20, 0x80, 0x40, 0x38],
            Arm64Fixture {
                registers: vec![("x1", 0x3000)],
                memory: vec![(0x3008, vec![0xab])],
            },
        ),
        (
            "sturb w0, [x1, #8]",
            vec![0x20, 0x80, 0x00, 0x38],
            Arm64Fixture {
                registers: vec![("w0", 0x1234_56ab), ("x1", 0x3000)],
                memory: vec![(0x3008, vec![0x00])],
            },
        ),
        (
            "ldrsb x0, [x1]",
            vec![0x20, 0x00, 0x80, 0x39],
            Arm64Fixture {
                registers: vec![("x1", 0x2000)],
                memory: vec![(0x2000, vec![0x81])],
            },
        ),
        (
            "ldrsh x0, [x1]",
            vec![0x20, 0x00, 0x80, 0x79],
            Arm64Fixture {
                registers: vec![("x1", 0x2000)],
                memory: vec![(0x2000, vec![0x01, 0x80])],
            },
        ),
        (
            "ldrsw x0, [x1]",
            vec![0x20, 0x00, 0x80, 0xb9],
            Arm64Fixture {
                registers: vec![("x1", 0x2000)],
                memory: vec![(0x2000, vec![0x01, 0x00, 0x00, 0x80])],
            },
        ),
        (
            "ldursh x0, [x1, #8]",
            vec![0x20, 0x80, 0x80, 0x78],
            Arm64Fixture {
                registers: vec![("x1", 0x3000)],
                memory: vec![(0x3008, vec![0x01, 0x80])],
            },
        ),
        (
            "ldursw x0, [x1, #8]",
            vec![0x20, 0x80, 0x80, 0xb8],
            Arm64Fixture {
                registers: vec![("x1", 0x3000)],
                memory: vec![(0x3008, vec![0x01, 0x00, 0x00, 0x80])],
            },
        ),
        (
            "ldursb x0, [x1, #8]",
            vec![0x20, 0x80, 0x80, 0x38],
            Arm64Fixture {
                registers: vec![("x1", 0x3000)],
                memory: vec![(0x3008, vec![0x81])],
            },
        ),
        (
            "ldurh w0, [x1, #8]",
            vec![0x20, 0x80, 0x40, 0x78],
            Arm64Fixture {
                registers: vec![("x1", 0x3000)],
                memory: vec![(0x3008, vec![0xcd, 0xab])],
            },
        ),
        (
            "sturh w0, [x1, #8]",
            vec![0x20, 0x80, 0x00, 0x78],
            Arm64Fixture {
                registers: vec![("w0", 0x1234_abcd), ("x1", 0x3000)],
                memory: vec![(0x3008, vec![0x00, 0x00])],
            },
        ),
        (
            "ldtr x0, [x1, #8]",
            vec![0x20, 0x88, 0x40, 0xf8],
            Arm64Fixture {
                registers: vec![("x1", 0x3000)],
                memory: vec![(0x3008, vec![0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11])],
            },
        ),
        (
            "sttr x0, [x1, #8]",
            vec![0x20, 0x88, 0x00, 0xf8],
            Arm64Fixture {
                registers: vec![("x0", 0x1122_3344_5566_7788), ("x1", 0x3000)],
                memory: vec![(0x3008, vec![0; 8])],
            },
        ),
        (
            "ldtrb w0, [x1, #8]",
            vec![0x20, 0x88, 0x40, 0x38],
            Arm64Fixture {
                registers: vec![("x1", 0x3000)],
                memory: vec![(0x3008, vec![0xab])],
            },
        ),
        (
            "sttrb w0, [x1, #8]",
            vec![0x20, 0x88, 0x00, 0x38],
            Arm64Fixture {
                registers: vec![("w0", 0x1234_56ab), ("x1", 0x3000)],
                memory: vec![(0x3008, vec![0x00])],
            },
        ),
        (
            "ldtrh w0, [x1, #8]",
            vec![0x20, 0x88, 0x40, 0x78],
            Arm64Fixture {
                registers: vec![("x1", 0x3000)],
                memory: vec![(0x3008, vec![0xcd, 0xab])],
            },
        ),
        (
            "sttrh w0, [x1, #8]",
            vec![0x20, 0x88, 0x00, 0x78],
            Arm64Fixture {
                registers: vec![("w0", 0x1234_abcd), ("x1", 0x3000)],
                memory: vec![(0x3008, vec![0x00, 0x00])],
            },
        ),
        (
            "ldtrsb x0, [x1, #8]",
            vec![0x20, 0x88, 0x80, 0x38],
            Arm64Fixture {
                registers: vec![("x1", 0x3000)],
                memory: vec![(0x3008, vec![0x81])],
            },
        ),
        (
            "ldtrsh x0, [x1, #8]",
            vec![0x20, 0x88, 0x80, 0x78],
            Arm64Fixture {
                registers: vec![("x1", 0x3000)],
                memory: vec![(0x3008, vec![0x01, 0x80])],
            },
        ),
        (
            "ldtrsw x0, [x1, #8]",
            vec![0x20, 0x88, 0x80, 0xb8],
            Arm64Fixture {
                registers: vec![("x1", 0x3000)],
                memory: vec![(0x3008, vec![0x01, 0x00, 0x00, 0x80])],
            },
        ),
        (
            "ldnp x0, x1, [x2]",
            vec![0x40, 0x04, 0x40, 0xa8],
            Arm64Fixture {
                registers: vec![("x2", 0x3000)],
                memory: vec![(
                    0x3000,
                    vec![
                        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd,
                        0xcc, 0xbb, 0xaa, 0x99,
                    ],
                )],
            },
        ),
        (
            "stnp x0, x1, [x2]",
            vec![0x40, 0x04, 0x00, 0xa8],
            Arm64Fixture {
                registers: vec![
                    ("x0", 0x1122_3344_5566_7788),
                    ("x1", 0x99aa_bbcc_ddee_ff00),
                    ("x2", 0x3000),
                ],
                memory: vec![(0x3000, vec![0; 16])],
            },
        ),
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
            "stp x0, x1, [x2]",
            vec![0x40, 0x04, 0x00, 0xa9],
            Arm64Fixture {
                registers: vec![
                    ("x0", 0x0102_0304_0506_0708),
                    ("x1", 0x1112_1314_1516_1718),
                    ("x2", 0x3000),
                ],
                memory: vec![(0x3000, vec![0; 16])],
            },
        ),
        (
            "ldpsw x0, x1, [x2]",
            vec![0x40, 0x04, 0x40, 0x69],
            Arm64Fixture {
                registers: vec![("x2", 0x3000)],
                memory: vec![(
                    0x3000,
                    vec![
                        0x01, 0x00, 0x00, 0x80, 0xfe, 0xff, 0xff, 0xff,
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
            "stp x0, x1, [sp, #-16]!",
            vec![0xe0, 0x07, 0xbf, 0xa9],
            Arm64Fixture {
                registers: vec![
                    ("x0", 0x1122_3344_5566_7788),
                    ("x1", 0x99aa_bbcc_ddee_ff00),
                    ("sp", 0x2ff0),
                ],
                memory: vec![(0x2fe0, vec![0; 16])],
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
            "stp x0, x1, [x2], #16",
            vec![0x40, 0x04, 0x81, 0xa8],
            Arm64Fixture {
                registers: vec![
                    ("x0", 0x0102_0304_0506_0708),
                    ("x1", 0x1112_1314_1516_1718),
                    ("x2", 0x3000),
                ],
                memory: vec![(0x3000, vec![0; 16])],
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
            "ldpsw x0, x1, [x2], #8",
            vec![0x40, 0x04, 0xc1, 0x68],
            Arm64Fixture {
                registers: vec![("x2", 0x3000)],
                memory: vec![(
                    0x3000,
                    vec![0x01, 0x00, 0x00, 0x80, 0xfe, 0xff, 0xff, 0xff],
                )],
            },
        ),
        (
            "ldpsw x0, x1, [sp, #-8]!",
            vec![0xe0, 0x07, 0xff, 0x69],
            Arm64Fixture {
                registers: vec![("sp", 0x2ff0)],
                memory: vec![(
                    0x2fe8,
                    vec![0x01, 0x00, 0x00, 0x80, 0xfe, 0xff, 0xff, 0xff],
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
            "stp w0, w1, [x2]",
            vec![0x40, 0x04, 0x00, 0x29],
            Arm64Fixture {
                registers: vec![
                    ("w0", 0x1234_5678),
                    ("w1", 0x89ab_cdef),
                    ("x2", 0x3000),
                ],
                memory: vec![(0x3000, vec![0; 8])],
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
            "stp w0, w1, [x2], #8",
            vec![0x40, 0x04, 0x81, 0x28],
            Arm64Fixture {
                registers: vec![
                    ("w0", 0x0102_0304),
                    ("w1", 0x1112_1314),
                    ("x2", 0x3000),
                ],
                memory: vec![(0x3000, vec![0; 8])],
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
            "stp w0, w1, [sp, #-8]!",
            vec![0xe0, 0x07, 0xbf, 0x29],
            Arm64Fixture {
                registers: vec![
                    ("w0", 0x1234_5678),
                    ("w1", 0x89ab_cdef),
                    ("sp", 0x2ff0),
                ],
                memory: vec![(0x2fe8, vec![0; 8])],
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
            "stp w0, w1, [sp], #8",
            vec![0xe0, 0x07, 0x81, 0x28],
            Arm64Fixture {
                registers: vec![
                    ("w0", 0x0102_0304),
                    ("w1", 0x1112_1314),
                    ("sp", 0x2fe8),
                ],
                memory: vec![(0x2fe8, vec![0; 8])],
            },
        ),
        (
            "ldr x0, [x1, x2]",
            vec![0x20, 0x68, 0x62, 0xf8],
            Arm64Fixture {
                registers: vec![("x1", 0x3000), ("x2", 0x10)],
                memory: vec![(0x3010, vec![0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11])],
            },
        ),
        (
            "str x0, [x1, x2]",
            vec![0x20, 0x68, 0x22, 0xf8],
            Arm64Fixture {
                registers: vec![("x0", 0x1122_3344_5566_7788), ("x1", 0x3000), ("x2", 0x10)],
                memory: vec![(0x3010, vec![0; 8])],
            },
        ),
        (
            "ldrb w0, [x1, x2]",
            vec![0x20, 0x68, 0x62, 0x38],
            Arm64Fixture {
                registers: vec![("x1", 0x3000), ("x2", 0x10)],
                memory: vec![(0x3010, vec![0xab])],
            },
        ),
        (
            "strb w0, [x1, x2]",
            vec![0x20, 0x68, 0x22, 0x38],
            Arm64Fixture {
                registers: vec![("w0", 0x1234_56ab), ("x1", 0x3000), ("x2", 0x10)],
                memory: vec![(0x3010, vec![0x00])],
            },
        ),
        (
            "ldrh w0, [x1, x2]",
            vec![0x20, 0x68, 0x62, 0x78],
            Arm64Fixture {
                registers: vec![("x1", 0x3000), ("x2", 0x10)],
                memory: vec![(0x3010, vec![0xcd, 0xab])],
            },
        ),
        (
            "strh w0, [x1, x2]",
            vec![0x20, 0x68, 0x22, 0x78],
            Arm64Fixture {
                registers: vec![("w0", 0x1234_abcd), ("x1", 0x3000), ("x2", 0x10)],
                memory: vec![(0x3010, vec![0x00, 0x00])],
            },
        ),
        (
            "ldrsb x0, [x1, x2]",
            vec![0x20, 0x68, 0xa2, 0x38],
            Arm64Fixture {
                registers: vec![("x1", 0x3000), ("x2", 0x10)],
                memory: vec![(0x3010, vec![0x81])],
            },
        ),
        (
            "ldrsh x0, [x1, x2]",
            vec![0x20, 0x68, 0xa2, 0x78],
            Arm64Fixture {
                registers: vec![("x1", 0x3000), ("x2", 0x10)],
                memory: vec![(0x3010, vec![0x01, 0x80])],
            },
        ),
        (
            "ldr w0, [x1, x2]",
            vec![0x20, 0x68, 0x62, 0xb8],
            Arm64Fixture {
                registers: vec![("x1", 0x3000), ("x2", 0x10)],
                memory: vec![(0x3010, vec![0x78, 0x56, 0x34, 0x12])],
            },
        ),
        (
            "str w0, [x1, x2]",
            vec![0x20, 0x68, 0x22, 0xb8],
            Arm64Fixture {
                registers: vec![("w0", 0x1234_5678), ("x1", 0x3000), ("x2", 0x10)],
                memory: vec![(0x3010, vec![0; 4])],
            },
        ),
        (
            "ldrsw x0, [x1, x2]",
            vec![0x20, 0x68, 0xa2, 0xb8],
            Arm64Fixture {
                registers: vec![("x1", 0x3000), ("x2", 0x10)],
                memory: vec![(0x3010, vec![0x01, 0x00, 0x00, 0x80])],
            },
        ),
        (
            "ldrsh w0, [x1, x2]",
            vec![0x20, 0x68, 0xe2, 0x78],
            Arm64Fixture {
                registers: vec![("x1", 0x3000), ("x2", 0x10)],
                memory: vec![(0x3010, vec![0x01, 0x80])],
            },
        ),
        (
            "ldrsb w0, [x1]",
            vec![0x20, 0x00, 0xc0, 0x39],
            Arm64Fixture {
                registers: vec![("x1", 0x2000)],
                memory: vec![(0x2000, vec![0x81])],
            },
        ),
        (
            "ldrsh w0, [x1]",
            vec![0x20, 0x00, 0xc0, 0x79],
            Arm64Fixture {
                registers: vec![("x1", 0x2000)],
                memory: vec![(0x2000, vec![0x01, 0x80])],
            },
        ),
        (
            "ldtrsb w0, [x1, #8]",
            vec![0x20, 0x88, 0xc0, 0x38],
            Arm64Fixture {
                registers: vec![("x1", 0x3000)],
                memory: vec![(0x3008, vec![0x81])],
            },
        ),
        (
            "ldtrsh w0, [x1, #8]",
            vec![0x20, 0x88, 0xc0, 0x78],
            Arm64Fixture {
                registers: vec![("x1", 0x3000)],
                memory: vec![(0x3008, vec![0x01, 0x80])],
            },
        ),
        (
            "stp x29, x30, [sp, #-16]!",
            vec![0xfd, 0x7b, 0xbf, 0xa9],
            Arm64Fixture {
                registers: vec![
                    ("x29", 0x1122_3344_5566_7788),
                    ("x30", 0x99aa_bbcc_ddee_ff00),
                    ("sp", 0x2ff0),
                ],
                memory: vec![(0x2fe0, vec![0; 16])],
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
            "stp x29, x30, [sp]",
            vec![0xfd, 0x7b, 0x00, 0xa9],
            Arm64Fixture {
                registers: vec![
                    ("x29", 0x0102_0304_0506_0708),
                    ("x30", 0x1112_1314_1516_1718),
                    ("sp", 0x2fe0),
                ],
                memory: vec![(0x2fe0, vec![0; 16])],
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
        ),
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
