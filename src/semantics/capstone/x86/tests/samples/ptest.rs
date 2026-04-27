use super::{
    I386Fixture, I386Register, X86FixtureSpec, X86Sample, assert_conformance_cases,
    assert_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

use super::super::support::{WideI386Fixture, interpret_amd64_wide_semantics};

const fn vec128(bytes: [u8; 16]) -> u128 {
    u128::from_le_bytes(bytes)
}

pub(crate) const SAMPLES: &[X86Sample] = &[
    X86Sample {
        mnemonic: "ptest",
        instruction: "ptest xmm0, xmm1",
        architecture: Architecture::AMD64,
        bytes: &[0x66, 0x0f, 0x38, 0x17, 0xc1],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "ptest",
        instruction: "vptest xmm0, xmm1",
        architecture: Architecture::AMD64,
        bytes: &[0xc4, 0xe2, 0x79, 0x17, 0xc1],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "ptest",
        instruction: "ptest xmm0, xmm1",
        architecture: Architecture::AMD64,
        bytes: &[0x66, 0x0f, 0x38, 0x17, 0xc1],
        expected_status: None,
        semantics_fixture: Some(X86FixtureSpec {
            registers: &[
                (
                    I386Register::Xmm0,
                    vec128([
                        0x10, 0x80, 0x20, 0x70, 0x30, 0x60, 0x40, 0x50, 0xaa, 0xbb, 0xcc, 0xdd,
                        0xee, 0xff, 0x11, 0x22,
                    ]),
                ),
                (
                    I386Register::Xmm1,
                    vec128([
                        0x01, 0xff, 0x02, 0xfe, 0x03, 0xfd, 0x04, 0xfc, 0x55, 0x44, 0x33, 0x22,
                        0x11, 0x00, 0x99, 0x88,
                    ]),
                ),
            ],
            eflags: 1 << 1,
            memory: &[],
        }),
        roundtrip_fixture: None,
    },
];

#[test]
fn ptest_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn ptest_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}

#[test]
fn vptest_semantics_wide_regression_stays_stable() {
    let ymm0 = vec![
        0x10, 0x80, 0x20, 0x70, 0x30, 0x60, 0x40, 0x50, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x11, 0x22, 0x01, 0x81, 0x02, 0x82, 0x03, 0x83, 0x04, 0x84, 0x05, 0x85, 0x06, 0x86,
        0x07, 0x87, 0x08, 0x88,
    ];
    let ymm1 = vec![
        0x01, 0xff, 0x02, 0xfe, 0x03, 0xfd, 0x04, 0xfc, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
        0x99, 0x88, 0xf0, 0x0f, 0xe1, 0x1e, 0xd2, 0x2d, 0xc3, 0x3c, 0xb4, 0x4b, 0xa5, 0x5a,
        0x96, 0x69, 0x87, 0x78,
    ];

    let (_, flags) = interpret_amd64_wide_semantics(
        "vptest ymm0, ymm1",
        &[0xc4, 0xe2, 0x7d, 0x17, 0xc1],
        WideI386Fixture {
            base: I386Fixture {
                registers: vec![],
                eflags: 1 << 1,
                memory: vec![],
            },
            wide_registers: vec![(I386Register::Ymm0, ymm0), (I386Register::Ymm1, ymm1)],
        },
    );

    assert!(!flags.zf, "vptest ymm0, ymm1: zf mismatch");
    assert!(!flags.cf, "vptest ymm0, ymm1: cf mismatch");
}
