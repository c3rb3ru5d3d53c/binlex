use super::{Arm64Sample, assert_sample_statuses};

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "fcvtn",
    instruction: "fcvtn v0.2s, v1.2d",
    bytes: &[0x20, 0x68, 0x61, 0x0e],
    expected_status: None,
    fixture: None,
}];

#[test]
fn fcvtn_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
