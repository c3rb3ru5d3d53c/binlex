use super::{Arm64Sample, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "ldxp",
    instruction: "ldxp	x0, x1, [x2]",
    bytes: &[0x40, 0x04, 0x7f, 0xc8],
    expected_status: Some(SemanticStatus::Complete),
    fixture: None,
}];

#[test]
fn ldxp_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
