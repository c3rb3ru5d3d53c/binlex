use super::{Arm64Sample, assert_sample_statuses};
pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "abs",
    instruction: "abs v0.16b, v1.16b",
    bytes: &[0x20, 0xb8, 0x20, 0x4e],
    expected_status: None,
    fixture: None,
}];

#[test]
fn abs_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
