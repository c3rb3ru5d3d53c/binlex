use super::{Arm64Sample, assert_sample_statuses};

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "fcvtas",
    instruction: "fcvtas x0, d1",
    bytes: &[0x20, 0x00, 0x64, 0x9e],
    expected_status: None,
    fixture: None,
}];

#[test]
fn fcvtas_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
