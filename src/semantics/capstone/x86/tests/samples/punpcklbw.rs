use super::super::support::{
    I386Fixture, I386Register, WideI386Fixture, assert_amd64_semantics_match_unicorn,
    assert_complete_semantics, assert_i386_instruction_roundtrip_match_unicorn,
    interpret_amd64_wide_semantics,
};
use crate::Architecture;

#[test]
fn punpcklbw_semantics_stay_complete() {
    let cases = [
        (
            "punpcklbw xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x60, 0xc1],
        ),
        (
            "vpunpcklbw xmm0, xmm2, xmm1",
            Architecture::AMD64,
            vec![0xc5, 0xe9, 0x60, 0xc1],
        ),
    ];

    for (name, architecture, bytes) in cases {
        assert_complete_semantics(name, architecture, &bytes);
    }
}

#[test]
fn punpcklbw_semantics_match_unicorn_transitions() {
    let xmm0 = u128::from_le_bytes([
        0x10, 0x80, 0x20, 0x70, 0x30, 0x60, 0x40, 0x50, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x11, 0x22,
    ]);
    let xmm1 = u128::from_le_bytes([
        0x01, 0xff, 0x02, 0xfe, 0x03, 0xfd, 0x04, 0xfc, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
        0x99, 0x88,
    ]);

    assert_amd64_semantics_match_unicorn(
        "punpcklbw xmm0, xmm1",
        &[0x66, 0x0f, 0x60, 0xc1],
        I386Fixture {
            registers: vec![(I386Register::Xmm0, xmm0), (I386Register::Xmm1, xmm1)],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}

#[test]
fn i386_roundtrip_punpcklbw_xmm0_xmm1_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "punpcklbw xmm0, xmm1",
        &[0x66, 0x0f, 0x60, 0xc1],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1122_3344),
                (I386Register::Ebx, 0x3000),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
                (
                    I386Register::Xmm0,
                    0x0011_2233_4455_6677_8899_aabb_ccdd_eeff,
                ),
                (
                    I386Register::Xmm1,
                    0xffee_ddcc_bbaa_9988_7766_5544_3322_1100,
                ),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}

#[test]
fn ymm_vpunpcklbw_semantics_wide_regression_stays_stable() {
    let ymm1 = vec![
        0x01, 0xff, 0x02, 0xfe, 0x03, 0xfd, 0x04, 0xfc, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
        0x99, 0x88, 0xf0, 0x0f, 0xe1, 0x1e, 0xd2, 0x2d, 0xc3, 0x3c, 0xb4, 0x4b, 0xa5, 0x5a,
        0x96, 0x69, 0x87, 0x78,
    ];
    let ymm2 = vec![
        0xde, 0xad, 0xbe, 0xef, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x13, 0x57,
        0x9b, 0xdf, 0x24, 0x42, 0x66, 0x81, 0xa5, 0xc3, 0xe7, 0xff, 0x18, 0x36, 0x54, 0x72,
        0x90, 0xab, 0xcd, 0xef,
    ];

    let (registers, _) = interpret_amd64_wide_semantics(
        "vpunpcklbw ymm0, ymm2, ymm1",
        &[0xc5, 0xed, 0x60, 0xc1],
        WideI386Fixture {
            base: I386Fixture {
                registers: vec![],
                eflags: 1 << 1,
                memory: vec![],
            },
            wide_registers: vec![
                (I386Register::Ymm0, vec![0; 32]),
                (I386Register::Ymm1, ymm1),
                (I386Register::Ymm2, ymm2),
            ],
        },
    );

    assert_eq!(
        registers.get("ymm0"),
        Some(&vec![
            0xde, 0x01, 0xad, 0xff, 0xbe, 0x02, 0xef, 0xfe, 0x10, 0x03, 0x32, 0xfd, 0x54,
            0x04, 0x76, 0xfc, 0x24, 0xf0, 0x42, 0x0f, 0x66, 0xe1, 0x81, 0x1e, 0xa5, 0xd2,
            0xc3, 0x2d, 0xe7, 0xc3, 0xff, 0x3c,
        ])
    );
}
