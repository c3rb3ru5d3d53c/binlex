use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "pcmpistri",
    instruction: "pcmpistri xmm0, xmm1, 0",
    architecture: Architecture::AMD64,
    bytes: &[0x66, 0x0f, 0x3a, 0x63, 0xc1, 0x00],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn pcmpistri_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
