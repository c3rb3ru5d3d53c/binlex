use super::{Arm64Sample, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "fcsel",
    instruction: "fcsel	d0, d1, d2, eq",
    bytes: &[0x20, 0x0c, 0x62, 0x1e],
    expected_status: Some(SemanticStatus::Complete),
    fixture: None,
}];

#[test]
fn fcsel_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
