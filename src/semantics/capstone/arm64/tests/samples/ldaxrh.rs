use super::{Arm64Sample, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "ldaxrh",
    instruction: "ldaxrh	w0, [x1]",
    bytes: &[0x20, 0xfc, 0x5f, 0x48],
    expected_status: Some(SemanticStatus::Complete),
    fixture: None,
}];

#[test]
fn ldaxrh_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
