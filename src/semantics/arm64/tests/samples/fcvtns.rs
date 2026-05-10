use super::{Arm64Sample, assert_sample_statuses};

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "fcvtns",
    instruction: "fcvtns x0, d1",
    bytes: &[0x20, 0x00, 0x60, 0x9e],
    expected_status: None,
    fixture: None,
}];

#[test]
fn fcvtns_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
