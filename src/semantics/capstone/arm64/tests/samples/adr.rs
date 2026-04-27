use super::{Arm64Sample, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "adr",
    instruction: "adr x0, #0",
    bytes: &[0x00, 0x00, 0x00, 0x10],
    expected_status: Some(SemanticStatus::Complete),
    fixture: None,
}];

#[test]
fn adr_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
