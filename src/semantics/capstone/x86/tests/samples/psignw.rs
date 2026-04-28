use super::{
    I386Register, X86FixtureSpec, X86Sample, assert_conformance_cases, assert_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

const XMM0: u128 = u128::from_le_bytes([
    0x10, 0x80, 0x20, 0x70, 0x30, 0x60, 0x40, 0x50, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11,
    0x22,
]);
const XMM1: u128 = u128::from_le_bytes([
    0x01, 0x00, 0xff, 0xff, 0x00, 0x00, 0xfe, 0xff, 0x34, 0x12, 0xcc, 0xed, 0x00, 0x00, 0xaa,
    0xff,
]);

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "psignw",
    instruction: "psignw xmm0, xmm1",
    architecture: Architecture::AMD64,
    bytes: &[0x66, 0x0f, 0x38, 0x09, 0xc1],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: Some(X86FixtureSpec {
        registers: &[(I386Register::Xmm0, XMM0), (I386Register::Xmm1, XMM1)],
        eflags: 1 << 1,
        memory: &[],
    }),
    roundtrip_fixture: None,
}];

#[test]
fn psignw_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn psignw_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
