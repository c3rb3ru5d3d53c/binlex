use super::{Arm64Sample, assert_sample_statuses};

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "cfinv",
    instruction: "cfinv",
    bytes: &[0x1f, 0x40, 0x00, 0xd5],
    expected_status: None,
    fixture: None,
}];

#[test]
fn cfinv_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
