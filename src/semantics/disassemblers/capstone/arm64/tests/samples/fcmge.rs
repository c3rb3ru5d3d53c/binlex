use super::{Arm64Sample, assert_sample_statuses};

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "fcmge",
    instruction: "fcmge v0.2d, v1.2d, v2.2d",
    bytes: &[0x20, 0xe4, 0x62, 0x6e],
    expected_status: None,
    fixture: None,
}];

#[test]
fn fcmge_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
