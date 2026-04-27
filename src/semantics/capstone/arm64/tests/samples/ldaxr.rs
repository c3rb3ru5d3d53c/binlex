use super::{Arm64Sample, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "ldaxr",
    instruction: "ldaxr	x0, [x1]",
    bytes: &[0x20, 0xfc, 0x5f, 0xc8],
    expected_status: Some(SemanticStatus::Complete),
    fixture: None,
}];

#[test]
fn ldaxr_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
