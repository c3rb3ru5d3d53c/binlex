use super::{Arm64Sample, assert_sample_statuses};

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "cmle",
    instruction: "cmle v0.16b, v1.16b, #0",
    bytes: &[0x20, 0x98, 0x20, 0x6e],
    expected_status: None,
    fixture: None,
}];

#[test]
fn cmle_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
