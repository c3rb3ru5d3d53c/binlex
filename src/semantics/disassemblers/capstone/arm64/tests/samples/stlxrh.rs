use super::{Arm64Sample, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "stlxrh",
    instruction: "stlxrh	w0, w1, [x2]",
    bytes: &[0x41, 0xfc, 0x00, 0x48],
    expected_status: Some(SemanticStatus::Complete),
    fixture: None,
}];

#[test]
fn stlxrh_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
