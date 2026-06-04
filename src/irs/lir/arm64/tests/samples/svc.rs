use super::{Arm64Sample, assert_sample_statuses};
use crate::irs::lir::LirStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "svc",
    instruction: "svc	#0",
    bytes: &[0x01, 0x00, 0x00, 0xd4],
    expected_status: Some(LirStatus::Complete),
    fixture: None,
}];

#[test]
fn svc_lir_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
