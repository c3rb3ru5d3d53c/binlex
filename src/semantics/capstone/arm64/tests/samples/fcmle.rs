use super::{Arm64Sample, assert_sample_statuses};

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "fcmle",
    instruction: "fcmle v0.2d, v1.2d, #0.0",
    bytes: &[0x20, 0xd8, 0xe0, 0x6e],
    expected_status: None,
    fixture: None,
}];

#[test]
fn fcmle_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
