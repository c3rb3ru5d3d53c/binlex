use super::{
    I386Register, X86FixtureSpec, X86Sample, assert_conformance_cases, assert_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

const XMM1_BYTES: [u8; 16] = [
    0x01, 0xff, 0x80, 0xfe, 0x7f, 0x81, 0x04, 0xfc, 0x55, 0x44, 0x33, 0xdd, 0xee, 0x00, 0x99,
    0x88,
];

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "pabsb",
    instruction: "pabsb xmm0, xmm1",
    architecture: Architecture::AMD64,
    bytes: &[0x66, 0x0f, 0x38, 0x1c, 0xc1],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: Some(X86FixtureSpec {
        registers: &[(I386Register::Xmm0, 0), (I386Register::Xmm1, u128::from_le_bytes(XMM1_BYTES))],
        eflags: 1 << 1,
        memory: &[],
    }),
    roundtrip_fixture: None,
}];

#[test]
fn pabsb_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn pabsb_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
