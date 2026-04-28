use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "vaddsubps",
    instruction: "vaddsubps xmm0, xmm1, xmm2",
    architecture: Architecture::AMD64,
    bytes: &[0xc5, 0xf3, 0xd0, 0xc2],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn vaddsubps_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
