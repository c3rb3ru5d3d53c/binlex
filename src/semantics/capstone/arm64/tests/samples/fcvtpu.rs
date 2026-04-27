use super::{Arm64Sample, assert_sample_statuses};

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "fcvtpu",
    instruction: "fcvtpu x0, d1",
    bytes: &[0x20, 0x00, 0x69, 0x9e],
    expected_status: None,
    fixture: None,
}];

#[test]
fn fcvtpu_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
