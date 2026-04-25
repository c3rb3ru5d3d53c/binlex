use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn vector_semantics_match_unicorn_transitions() {
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
            "movi v0.16b, #0",
            vec![0x00, 0xe4, 0x00, 0x4f],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
        (
            "movi v0.8b, #255",
            vec![0xe0, 0xe7, 0x07, 0x0f],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
        (
            "movi v1.16b, #255",
            vec![0xe1, 0xe7, 0x07, 0x4f],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
        (
            "movi v1.8b, #1",
            vec![0x21, 0xe4, 0x00, 0x0f],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
        (
            "movi v0.2d, #0000000000000000",
            vec![0x00, 0xe4, 0x00, 0x6f],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
        (
            "movi v0.2d, #0xffffffffffffffff",
            vec![0xe0, 0xe7, 0x07, 0x6f],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
        (
            "movi v0.2s, #1",
            vec![0x20, 0x04, 0x00, 0x0f],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
        (
            "movi v0.2s, #2",
            vec![0x40, 0x04, 0x00, 0x0f],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
        (
            "movi d0, #0000000000000000",
            vec![0x00, 0xe4, 0x00, 0x2f],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
        (
            "movi d0, #0xffffffffffffffff",
            vec![0xe0, 0xe7, 0x07, 0x2f],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
        (
            "movi v2.2d, #0xffffffffffffffff",
            vec![0xe2, 0xe7, 0x07, 0x6f],
            Arm64Fixture {
                registers: vec![],
                memory: vec![],
            },
        ),
        (
            "dup v0.2d, x1",
            vec![0x20, 0x0c, 0x08, 0x4e],
            Arm64Fixture {
                registers: vec![("x1", 0x1122_3344_5566_7788)],
                memory: vec![],
            },
        ),
        (
            "dup v0.16b, w1",
            vec![0x20, 0x0c, 0x01, 0x4e],
            Arm64Fixture {
                registers: vec![("w1", 0x1234_56ab)],
                memory: vec![],
            },
        ),
        (
            "rev64 v0.16b, v1.16b",
            vec![0x20, 0x08, 0x20, 0x4e],
            Arm64Fixture {
                registers: vec![
                    ("v1", 0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00u128),
                ],
                memory: vec![],
            },
        ),
        (
            "rev64 v0.2s, v1.2s",
            vec![0x20, 0x08, 0xa0, 0x0e],
            Arm64Fixture {
                registers: vec![("v1", 0x0000_0000_0000_0000_1122_3344_5566_7788u128)],
                memory: vec![],
            },
        ),
        (
            "cnt v0.8b, v1.8b",
            vec![0x20, 0x58, 0x20, 0x0e],
            Arm64Fixture {
                registers: vec![("v1", 0x0000_0000_0000_0000_f0ff_5501_7f80_0000u128)],
                memory: vec![],
            },
        ),
        (
            "cnt v0.16b, v1.16b",
            vec![0x20, 0x58, 0x20, 0x4e],
            Arm64Fixture {
                registers: vec![
                    ("v1", 0xf0ff_5501_7f80_0000_1122_3344_5566_7788u128),
                ],
                memory: vec![],
            },
        ),
        (
            "cmeq v0.16b, v1.16b, v2.16b",
            vec![0x20, 0x8c, 0x22, 0x6e],
            Arm64Fixture {
                registers: vec![
                    ("v1", 0x100f_0e0d_0c0b_0a09_0807_0605_0403_0201u128),
                    ("v2", 0x1001_0e0d_0cff_0a09_aa07_0605_0400_0201u128),
                ],
                memory: vec![],
            },
        ),
        (
            "cmhi v0.16b, v1.16b, v2.16b",
            vec![0x20, 0x34, 0x22, 0x6e],
            Arm64Fixture {
                registers: vec![
                    ("v1", 0x100f_0e0d_0c0b_0a09_0807_0605_0403_0201u128),
                    ("v2", 0x0f10_0e00_0cff_0a09_aa08_0604_0402_0100u128),
                ],
                memory: vec![],
            },
        ),
        (
            "cmeq v0.2s, v1.2s, v2.2s",
            vec![0x20, 0x8c, 0xa2, 0x2e],
            Arm64Fixture {
                registers: vec![
                    ("v1", 0x0000_0000_0000_0000_0000_0002_0000_0001u128),
                    ("v2", 0x0000_0000_0000_0000_0000_0003_0000_0001u128),
                ],
                memory: vec![],
            },
        ),
        (
            "cmhi v0.2s, v1.2s, v2.2s",
            vec![0x20, 0x34, 0xa2, 0x2e],
            Arm64Fixture {
                registers: vec![
                    ("v1", 0x0000_0000_0000_0000_0000_0004_0000_0002u128),
                    ("v2", 0x0000_0000_0000_0000_0000_0003_0000_0005u128),
                ],
                memory: vec![],
            },
        ),
        (
            "uzp1 v0.16b, v1.16b, v2.16b",
            vec![0x20, 0x18, 0x02, 0x4e],
            Arm64Fixture {
                registers: vec![
                    ("v1", 0x0f0e_0d0c_0b0a_0908_0706_0504_0302_0100u128),
                    ("v2", 0x1f1e_1d1c_1b1a_1918_1716_1514_1312_1110u128),
                ],
                memory: vec![],
            },
        ),
        (
            "uzp1 v0.4s, v1.4s, v2.4s",
            vec![0x20, 0x18, 0x82, 0x4e],
            Arm64Fixture {
                registers: vec![
                    ("v1", 0x0000_0004_0000_0003_0000_0002_0000_0001u128),
                    ("v2", 0x0000_0008_0000_0007_0000_0006_0000_0005u128),
                ],
                memory: vec![],
            },
        ),
        (
            "addv s0, v1.4s",
            vec![0x20, 0xb8, 0xb1, 0x4e],
            Arm64Fixture {
                registers: vec![("v1", 0x0000_0004_0000_0003_0000_0002_0000_0001u128)],
                memory: vec![],
            },
        ),
        (
            "uaddlv h0, v1.8b",
            vec![0x20, 0x38, 0x30, 0x2e],
            Arm64Fixture {
                registers: vec![("v1", 0x0000_0000_0000_0000_0807_0605_0403_0201u128)],
                memory: vec![],
            },
        ),
        (
            "uaddlv h0, v1.16b",
            vec![0x20, 0x38, 0x30, 0x6e],
            Arm64Fixture {
                registers: vec![
                    ("v1", 0x100f_0e0d_0c0b_0a09_0807_0605_0403_0201u128),
                ],
                memory: vec![],
            },
        ),
        (
            "ld1 {v0.d}[1], [x1]",
            vec![0x20, 0x84, 0x40, 0x4d],
            Arm64Fixture {
                registers: vec![
                    ("v0", 0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00u128),
                    ("x1", 0x5000),
                ],
                memory: vec![(0x5000, vec![0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11])],
            },
        ),
        (
            "ld1 {v1.s}[1], [x11]",
            vec![0x61, 0x91, 0x40, 0x0d],
            Arm64Fixture {
                registers: vec![
                    ("v1", 0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00u128),
                    ("x11", 0x6000),
                ],
                memory: vec![(0x6000, vec![0x78, 0x56, 0x34, 0x12])],
            },
        ),
        (
            "sshll v0.8h, v1.8b, #0",
            vec![0x20, 0xa4, 0x08, 0x0f],
            Arm64Fixture {
                registers: vec![("v1", 0x0000_0000_0000_0000_aa55_f010_ff01_7f80u128)],
                memory: vec![],
            },
        ),
        (
            "sshll v0.4s, v1.4h, #0",
            vec![0x20, 0xa4, 0x10, 0x0f],
            Arm64Fixture {
                registers: vec![("v1", 0x0000_0000_0000_0000_0000_0000_8001_7fffu128)],
                memory: vec![],
            },
        ),
        (
            "sshll v1.4s, v0.4h, #0",
            vec![0x01, 0xa4, 0x10, 0x0f],
            Arm64Fixture {
                registers: vec![("v0", 0x0000_0000_0000_0000_0000_0000_8001_7fffu128)],
                memory: vec![],
            },
        ),
        (
            "sshll v0.2d, v1.2s, #0",
            vec![0x20, 0xa4, 0x20, 0x0f],
            Arm64Fixture {
                registers: vec![("v1", 0x0000_0000_0000_0000_ffff_ffff_7fff_ffffu128)],
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
        ),
        (
            "fabs d0, d1",
            vec![0x20, 0xc0, 0x60, 0x1e],
            Arm64Fixture {
                registers: vec![("d1", 0xc008_0000_0000_0000)],
                memory: vec![],
            },
        ),
        (
            "fneg d0, d1",
            vec![0x20, 0x40, 0x61, 0x1e],
            Arm64Fixture {
                registers: vec![("d1", 0x4008_0000_0000_0000)],
                memory: vec![],
            },
        ),
        (
            "fadd d0, d1, d2",
            vec![0x20, 0x28, 0x62, 0x1e],
            Arm64Fixture {
                registers: vec![
                    ("d1", 0x4008_0000_0000_0000),
                    ("d2", 0x4014_0000_0000_0000),
                ],
                memory: vec![],
            },
        ),
        (
            "fsub d0, d1, d2",
            vec![0x20, 0x38, 0x62, 0x1e],
            Arm64Fixture {
                registers: vec![
                    ("d1", 0x4014_0000_0000_0000),
                    ("d2", 0x4008_0000_0000_0000),
                ],
                memory: vec![],
            },
        ),
        (
            "fmul d0, d1, d2",
            vec![0x20, 0x08, 0x62, 0x1e],
            Arm64Fixture {
                registers: vec![
                    ("d1", 0x4008_0000_0000_0000),
                    ("d2", 0x4014_0000_0000_0000),
                ],
                memory: vec![],
            },
        ),
        (
            "fnmul d0, d1, d2",
            vec![0x20, 0x88, 0x62, 0x1e],
            Arm64Fixture {
                registers: vec![
                    ("d1", 0x4008_0000_0000_0000),
                    ("d2", 0x4014_0000_0000_0000),
                ],
                memory: vec![],
            },
        ),
        (
            "fdiv d0, d1, d2",
            vec![0x20, 0x18, 0x62, 0x1e],
            Arm64Fixture {
                registers: vec![
                    ("d1", 0x4014_0000_0000_0000),
                    ("d2", 0x4008_0000_0000_0000),
                ],
                memory: vec![],
            },
        ),
        (
            "fmin d0, d1, d2",
            vec![0x20, 0x58, 0x62, 0x1e],
            Arm64Fixture {
                registers: vec![
                    ("d1", 0x4008_0000_0000_0000),
                    ("d2", 0x4014_0000_0000_0000),
                ],
                memory: vec![],
            },
        ),
        (
            "fmax d0, d1, d2",
            vec![0x20, 0x48, 0x62, 0x1e],
            Arm64Fixture {
                registers: vec![
                    ("d1", 0x4008_0000_0000_0000),
                    ("d2", 0x4014_0000_0000_0000),
                ],
                memory: vec![],
            },
        ),
        (
            "fmadd d0, d1, d2, d3",
            vec![0x20, 0x0c, 0x42, 0x1f],
            Arm64Fixture {
                registers: vec![
                    ("d1", 0x4000_0000_0000_0000),
                    ("d2", 0x4014_0000_0000_0000),
                    ("d3", 0x4008_0000_0000_0000),
                ],
                memory: vec![],
            },
        ),
        (
            "fmsub d0, d1, d2, d3",
            vec![0x20, 0x8c, 0x42, 0x1f],
            Arm64Fixture {
                registers: vec![
                    ("d1", 0x4000_0000_0000_0000),
                    ("d2", 0x4008_0000_0000_0000),
                    ("d3", 0x4014_0000_0000_0000),
                ],
                memory: vec![],
            },
        ),
        (
            "scvtf d0, x1",
            vec![0x20, 0x00, 0x62, 0x9e],
            Arm64Fixture {
                registers: vec![("x1", 42)],
                memory: vec![],
            },
        ),
        (
            "ucvtf d0, x1",
            vec![0x20, 0x00, 0x63, 0x9e],
            Arm64Fixture {
                registers: vec![("x1", 42)],
                memory: vec![],
            },
        ),
        (
            "fcvtzs x0, d1",
            vec![0x20, 0x00, 0x78, 0x9e],
            Arm64Fixture {
                registers: vec![("d1", 0x4045_0000_0000_0000)],
                memory: vec![],
            },
        ),
        (
            "fcvtzu x0, d1",
            vec![0x20, 0x00, 0x79, 0x9e],
            Arm64Fixture {
                registers: vec![("d1", 0x4045_0000_0000_0000)],
                memory: vec![],
            },
        ),
        (
            "fcmp d0, d1",
            vec![0x00, 0x20, 0x61, 0x1e],
            Arm64Fixture {
                registers: vec![
                    ("n", 0),
                    ("z", 1),
                    ("c", 0),
                    ("v", 0),
                    ("d0", 0x4008_0000_0000_0000),
                    ("d1", 0x4014_0000_0000_0000),
                ],
                memory: vec![],
            },
        ),
        (
            "fcmp s0, s1",
            vec![0x00, 0x20, 0x21, 0x1e],
            Arm64Fixture {
                registers: vec![
                    ("n", 0),
                    ("z", 1),
                    ("c", 0),
                    ("v", 0),
                    ("s0", 0x4040_0000),
                    ("s1", 0x4080_0000),
                ],
                memory: vec![],
            },
        ),
        (
            "fcmp d0, #0.0",
            vec![0x08, 0x20, 0x60, 0x1e],
            Arm64Fixture {
                registers: vec![
                    ("n", 0),
                    ("z", 1),
                    ("c", 0),
                    ("v", 0),
                    ("d0", 0x4008_0000_0000_0000),
                ],
                memory: vec![],
            },
        ),
        (
            "fcmp s0, #0.0",
            vec![0x08, 0x20, 0x20, 0x1e],
            Arm64Fixture {
                registers: vec![
                    ("n", 0),
                    ("z", 1),
                    ("c", 0),
                    ("v", 0),
                    ("s0", 0x4040_0000),
                ],
                memory: vec![],
            },
        ),
        (
            "fcmpe d0, d1",
            vec![0x00, 0x20, 0x61, 0x1e],
            Arm64Fixture {
                registers: vec![
                    ("n", 0),
                    ("z", 1),
                    ("c", 0),
                    ("v", 0),
                    ("d0", 0x4014_0000_0000_0000),
                    ("d1", 0x4008_0000_0000_0000),
                ],
                memory: vec![],
            },
        ),
        (
            "fcmpe s0, s1",
            vec![0x10, 0x20, 0x21, 0x1e],
            Arm64Fixture {
                registers: vec![
                    ("n", 0),
                    ("z", 1),
                    ("c", 0),
                    ("v", 0),
                    ("s0", 0x4080_0000),
                    ("s1", 0x4040_0000),
                ],
                memory: vec![],
            },
        ),
        (
            "fcmpe d0, #0.0",
            vec![0x18, 0x20, 0x60, 0x1e],
            Arm64Fixture {
                registers: vec![
                    ("n", 0),
                    ("z", 1),
                    ("c", 0),
                    ("v", 0),
                    ("d0", 0x4008_0000_0000_0000),
                ],
                memory: vec![],
            },
        ),
        (
            "fcmpe s0, #0.0",
            vec![0x18, 0x20, 0x20, 0x1e],
            Arm64Fixture {
                registers: vec![
                    ("n", 0),
                    ("z", 1),
                    ("c", 0),
                    ("v", 0),
                    ("s0", 0x4040_0000),
                ],
                memory: vec![],
            },
        ),
        (
            "fccmp d0, d1, #0, eq",
            vec![0x00, 0x04, 0x61, 0x1e],
            Arm64Fixture {
                registers: vec![
                    ("n", 0),
                    ("z", 1),
                    ("c", 0),
                    ("v", 0),
                    ("d0", 0x4008_0000_0000_0000),
                    ("d1", 0x4014_0000_0000_0000),
                ],
                memory: vec![],
            },
        ),
        (
            "fccmp d0, d1, #0, eq",
            vec![0x00, 0x04, 0x61, 0x1e],
            Arm64Fixture {
                registers: vec![
                    ("n", 0),
                    ("z", 0),
                    ("c", 0),
                    ("v", 0),
                    ("d0", 0x4008_0000_0000_0000),
                    ("d1", 0x4014_0000_0000_0000),
                ],
                memory: vec![],
            },
        ),
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
