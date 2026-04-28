use super::{
    I386Register, X86FixtureSpec, X86Sample, assert_conformance_cases, assert_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

const XMM0_BYTES: [u8; 16] = [
    0x10, 0x80, 0x20, 0x70, 0x30, 0x60, 0x40, 0x50, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11,
    0x22,
];
const XMM1_BYTES: [u8; 16] = [
    0x01, 0xff, 0x02, 0xfe, 0x03, 0xfd, 0x04, 0xfc, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x99,
    0x88,
];

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "psubusb",
    instruction: "psubusb xmm0, xmm1",
    architecture: Architecture::AMD64,
    bytes: &[0x66, 0x0f, 0xd8, 0xc1],
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
}];

#[test]
fn psubusb_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn psubusb_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
