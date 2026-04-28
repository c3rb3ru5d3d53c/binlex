use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "vpsrlq",
    instruction: "vpsrlq xmm0, xmm1, 1",
    architecture: Architecture::AMD64,
    bytes: &[0xc5, 0xf9, 0x73, 0xd1, 0x01],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn vpsrlq_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
