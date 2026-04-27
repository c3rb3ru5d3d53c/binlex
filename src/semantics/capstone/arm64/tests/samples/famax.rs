use super::{Arm64Sample, assert_sample_statuses};

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "famax",
    instruction: "famax v0.2d, v1.2d, v2.2d",
    bytes: &[0x20, 0xdc, 0xe2, 0x4e],
    expected_status: None,
    fixture: None,
}];

#[test]
fn famax_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
