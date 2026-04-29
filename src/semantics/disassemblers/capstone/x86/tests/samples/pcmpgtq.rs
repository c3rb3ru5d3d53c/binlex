use super::{
    I386Register, X86FixtureSpec, X86Sample, assert_conformance_cases, assert_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

const XMM0_BYTES: [u8; 16] = [
    0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0xf8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff,
];
const XMM1_BYTES: [u8; 16] = [
    0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00,
];
const XMM2_BYTES: [u8; 16] = [
    0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff,
];

pub(crate) const SAMPLES: &[X86Sample] = &[
    X86Sample {
        mnemonic: "pcmpgtq",
        instruction: "pcmpgtq xmm0, xmm1",
        architecture: Architecture::AMD64,
        bytes: &[0x66, 0x0f, 0x38, 0x37, 0xc1],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Xmm0, u128::from_le_bytes(XMM0_BYTES)),
                (I386Register::Xmm1, u128::from_le_bytes(XMM1_BYTES)),
            ],
            eflags: 1 << 1,
            memory: &[],
        }),
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "pcmpgtq",
        instruction: "vpcmpgtq xmm0, xmm1, xmm2",
        architecture: Architecture::AMD64,
        bytes: &[0xc4, 0xe2, 0x71, 0x37, 0xc2],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Xmm1, u128::from_le_bytes(XMM1_BYTES)),
                (I386Register::Xmm2, u128::from_le_bytes(XMM2_BYTES)),
            ],
            eflags: 1 << 1,
            memory: &[],
        }),
        roundtrip_fixture: None,
    },
];

#[test]
fn pcmpgtq_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn pcmpgtq_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
