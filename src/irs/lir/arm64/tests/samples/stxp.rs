use super::{Arm64Sample, assert_sample_statuses};
use crate::irs::lir::LirStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "stxp",
    instruction: "stxp	w0, x1, x2, [x3]",
    bytes: &[0x61, 0x08, 0x20, 0xc8],
    expected_status: Some(LirStatus::Complete),
    fixture: None,
}];

#[test]
fn stxp_lir_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
