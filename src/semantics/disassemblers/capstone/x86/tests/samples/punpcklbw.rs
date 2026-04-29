use super::{
    I386Register, X86FixtureSpec, X86Sample, assert_conformance_cases, assert_roundtrip_cases,
    assert_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

use super::super::support::{I386Fixture, WideI386Fixture, interpret_amd64_wide_semantics};

const XMM0: u128 = u128::from_le_bytes([
    0x10, 0x80, 0x20, 0x70, 0x30, 0x60, 0x40, 0x50, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11,
    0x22,
]);
const XMM1: u128 = u128::from_le_bytes([
    0x01, 0xff, 0x02, 0xfe, 0x03, 0xfd, 0x04, 0xfc, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x99,
    0x88,
]);

pub(crate) const SAMPLES: &[X86Sample] = &[
    X86Sample {
        mnemonic: "punpcklbw",
        instruction: "punpcklbw xmm0, xmm1",
        architecture: Architecture::AMD64,
        bytes: &[0x66, 0x0f, 0x60, 0xc1],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "punpcklbw",
        instruction: "vpunpcklbw xmm0, xmm2, xmm1",
        architecture: Architecture::AMD64,
        bytes: &[0xc5, 0xe9, 0x60, 0xc1],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "punpcklbw",
        instruction: "punpcklbw xmm0, xmm1",
        architecture: Architecture::AMD64,
        bytes: &[0x66, 0x0f, 0x60, 0xc1],
        expected_status: None,
        semantics_fixture: Some(X86FixtureSpec {
            registers: &[(I386Register::Xmm0, XMM0), (I386Register::Xmm1, XMM1)],
            eflags: 1 << 1,
            memory: &[],
        }),
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "punpcklbw",
        instruction: "punpcklbw xmm0, xmm1",
        architecture: Architecture::I386,
        bytes: &[0x66, 0x0f, 0x60, 0xc1],
        expected_status: None,
        semantics_fixture: None,
        roundtrip_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Eax, 0x1122_3344),
                (I386Register::Ebx, 0x3000),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
                (I386Register::Xmm0, 0x0011_2233_4455_6677_8899_aabb_ccdd_eeff),
                (I386Register::Xmm1, 0xffee_ddcc_bbaa_9988_7766_5544_3322_1100),
            ],
            eflags: 0x202,
            memory: &[],
        }),
    },
];

#[test]
fn punpcklbw_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn punpcklbw_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}

#[test]
fn punpcklbw_roundtrip_matches_unicorn() {
    assert_roundtrip_cases(SAMPLES);
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
            0xde, 0x01, 0xad, 0xff, 0xbe, 0x02, 0xef, 0xfe, 0x10, 0x03, 0x32, 0xfd, 0x54, 0x04,
            0x76, 0xfc, 0x24, 0xf0, 0x42, 0x0f, 0x66, 0xe1, 0x81, 0x1e, 0xa5, 0xd2, 0xc3, 0x2d,
            0xe7, 0xc3, 0xff, 0x3c,
        ])
    );
}
