use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "ldmxcsr",
    instruction: "ldmxcsr dword ptr [rax]",
    architecture: Architecture::AMD64,
    bytes: &[0x0f, 0xae, 0x10],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn ldmxcsr_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
