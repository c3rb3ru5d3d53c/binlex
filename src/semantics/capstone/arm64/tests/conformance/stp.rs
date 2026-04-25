use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn stp_semantics_match_unicorn_transitions() {
    let cases = [
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
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
