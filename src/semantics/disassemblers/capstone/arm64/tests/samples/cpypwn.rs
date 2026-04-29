use super::{Arm64Sample, assert_sample_statuses};

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "cpypwn",
    instruction: "cpypwn [x0]!, [x1]!, x2!",
    bytes: &[0x40, 0x44, 0x01, 0x1d],
    expected_status: None,
    fixture: None,
}];

#[test]
fn cpypwn_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
