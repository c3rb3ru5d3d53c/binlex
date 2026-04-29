use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "unpckhps",
    instruction: "unpckhps xmm0, xmm1",
    architecture: Architecture::AMD64,
    bytes: &[0x0f, 0x15, 0xc1],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn unpckhps_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
