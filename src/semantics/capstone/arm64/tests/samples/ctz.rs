use super::{Arm64Sample, assert_sample_statuses};

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "ctz",
    instruction: "ctz x0, x1",
    bytes: &[0x20, 0x18, 0xc0, 0xda],
    expected_status: None,
    fixture: None,
}];

#[test]
fn ctz_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
