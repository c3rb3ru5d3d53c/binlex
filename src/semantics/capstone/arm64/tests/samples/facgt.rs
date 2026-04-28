use super::{Arm64Sample, assert_sample_statuses};

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "facgt",
    instruction: "facgt v0.2d, v1.2d, v2.2d",
    bytes: &[0x20, 0xec, 0xe2, 0x6e],
    expected_status: None,
    fixture: None,
}];

#[test]
fn facgt_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
