use super::{Arm64Sample, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "ldxrh",
    instruction: "ldxrh	w0, [x1]",
    bytes: &[0x20, 0x7c, 0x5f, 0x48],
    expected_status: Some(SemanticStatus::Complete),
    fixture: None,
}];

#[test]
fn ldxrh_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
