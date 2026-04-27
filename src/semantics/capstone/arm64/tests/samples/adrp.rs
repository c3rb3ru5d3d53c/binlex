use super::{Arm64Sample, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "adrp",
    instruction: "adrp x0, #0",
    bytes: &[0x00, 0x00, 0x00, 0x90],
    expected_status: Some(SemanticStatus::Complete),
    fixture: None,
}];

#[test]
fn adrp_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
