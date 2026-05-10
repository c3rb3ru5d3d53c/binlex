use super::{Arm64Sample, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "movn",
    instruction: "mov	x0, #-305397761                 // =0xffffffffedcbffff",
    bytes: &[0x80, 0x46, 0xa2, 0x92],
    expected_status: Some(SemanticStatus::Complete),
    fixture: None,
}];

#[test]
fn movn_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
