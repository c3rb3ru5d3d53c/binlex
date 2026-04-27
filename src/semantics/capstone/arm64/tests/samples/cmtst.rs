use super::{Arm64Sample, assert_sample_statuses};

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "cmtst",
    instruction: "cmtst v0.16b, v1.16b, v2.16b",
    bytes: &[0x20, 0x8c, 0x22, 0x4e],
    expected_status: None,
    fixture: None,
}];

#[test]
fn cmtst_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
