use super::{Arm64Sample, assert_sample_statuses};

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "cmlt",
    instruction: "cmlt v0.16b, v1.16b, #0",
    bytes: &[0x20, 0xa8, 0x20, 0x4e],
    expected_status: None,
    fixture: None,
}];

#[test]
fn cmlt_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
