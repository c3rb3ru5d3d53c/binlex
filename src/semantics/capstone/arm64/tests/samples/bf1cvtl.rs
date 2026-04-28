use super::{Arm64Sample, assert_sample_statuses};

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "bf1cvtl",
    instruction: "bf1cvtl v0.8h, v1.8b",
    bytes: &[0x20, 0x78, 0xa1, 0x2e],
    expected_status: None,
    fixture: None,
}];

#[test]
fn bf1cvtl_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
