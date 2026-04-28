use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "verr",
    instruction: "verr ax",
    architecture: Architecture::I386,
    bytes: &[0x0f, 0x00, 0xe0],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn verr_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
