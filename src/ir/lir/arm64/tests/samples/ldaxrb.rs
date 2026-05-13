use super::{Arm64Sample, assert_sample_statuses};
use crate::ir::lir::LirStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "ldaxrb",
    instruction: "ldaxrb	w0, [x1]",
    bytes: &[0x20, 0xfc, 0x5f, 0x08],
    expected_status: Some(LirStatus::Complete),
    fixture: None,
}];

#[test]
fn ldaxrb_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
