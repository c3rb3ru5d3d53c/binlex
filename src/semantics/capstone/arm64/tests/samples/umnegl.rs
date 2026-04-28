use super::{Arm64Sample, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "umnegl",
    instruction: "umnegl	x0, w1, w2",
    bytes: &[0x20, 0xfc, 0xa2, 0x9b],
    expected_status: Some(SemanticStatus::Complete),
    fixture: None,
}];

#[test]
fn umnegl_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
