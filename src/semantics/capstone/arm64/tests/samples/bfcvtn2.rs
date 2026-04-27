use super::{Arm64Sample, assert_sample_statuses};
pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "bfcvtn2",
    instruction: "bfcvtn2 v0.8h, v1.4s",
    bytes: &[0x20, 0x68, 0xa1, 0x4e],
    expected_status: None,
    fixture: None,
}];

#[test]
fn bfcvtn2_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
