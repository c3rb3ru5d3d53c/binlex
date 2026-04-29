use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "fidivr",
    instruction: "fidivr dword ptr [rax]",
    architecture: Architecture::AMD64,
    bytes: &[0xda, 0x38],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn fidivr_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
