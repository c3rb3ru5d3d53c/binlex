use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "psrlq",
    instruction: "psrlq xmm0, 1",
    architecture: Architecture::AMD64,
    bytes: &[0x66, 0x0f, 0x73, 0xd0, 0x01],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn psrlq_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
