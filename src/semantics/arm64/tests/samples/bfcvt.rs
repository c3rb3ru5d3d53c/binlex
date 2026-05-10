use super::{Arm64Sample, assert_sample_statuses};
pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "bfcvt",
    instruction: "bfcvt h0, s1",
    bytes: &[0x20, 0x40, 0x63, 0x1e],
    expected_status: None,
    fixture: None,
}];

#[test]
fn bfcvt_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
