use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "cvttps2dq",
    instruction: "cvttps2dq xmm0, xmm1",
    architecture: Architecture::AMD64,
    bytes: &[0xf3, 0x0f, 0x5b, 0xc1],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn cvttps2dq_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
