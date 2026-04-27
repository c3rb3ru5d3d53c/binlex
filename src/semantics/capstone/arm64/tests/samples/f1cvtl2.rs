use super::{Arm64Sample, assert_sample_statuses};

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "f1cvtl2",
    instruction: "f1cvtl2 v0.8h, v1.16b",
    bytes: &[0x20, 0x78, 0x21, 0x6e],
    expected_status: None,
    fixture: None,
}];

#[test]
fn f1cvtl2_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
