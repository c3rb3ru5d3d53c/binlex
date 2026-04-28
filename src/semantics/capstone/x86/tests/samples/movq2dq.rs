use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "movq2dq",
    instruction: "movq2dq xmm0, mm1",
    architecture: Architecture::AMD64,
    bytes: &[0xf3, 0x0f, 0xd6, 0xc1],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn movq2dq_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
