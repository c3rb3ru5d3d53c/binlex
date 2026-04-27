use super::{Arm64Sample, assert_sample_statuses};

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "bfdot",
    instruction: "bfdot v0.2s, v1.4h, v2.4h",
    bytes: &[0x20, 0xfc, 0x42, 0x2e],
    expected_status: None,
    fixture: None,
}];

#[test]
fn bfdot_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
