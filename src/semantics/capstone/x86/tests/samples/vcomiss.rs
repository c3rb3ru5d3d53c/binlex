use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "vcomiss",
    instruction: "vcomiss xmm0, xmm1",
    architecture: Architecture::AMD64,
    bytes: &[0xc5, 0xf8, 0x2f, 0xc1],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn vcomiss_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
