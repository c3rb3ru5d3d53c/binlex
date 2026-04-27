use super::{Arm64Sample, assert_sample_statuses};

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "fcvtl2",
    instruction: "fcvtl2 v0.2d, v1.4s",
    bytes: &[0x20, 0x78, 0x61, 0x4e],
    expected_status: None,
    fixture: None,
}];

#[test]
fn fcvtl2_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
