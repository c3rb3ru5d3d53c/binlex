use super::{Arm64Sample, assert_sample_statuses};
pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "bfcvtn",
    instruction: "bfcvtn v0.4h, v1.4s",
    bytes: &[0x20, 0x68, 0xa1, 0x0e],
    expected_status: None,
    fixture: None,
}];

#[test]
fn bfcvtn_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
