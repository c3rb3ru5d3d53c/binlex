use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "fdivr",
    instruction: "fdivr dword ptr [eax]",
    architecture: Architecture::I386,
    bytes: &[0xd8, 0x38],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn fdivr_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
