use super::{Arm64Sample, assert_sample_statuses};

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "cpypwt",
    instruction: "cpypwt [x0]!, [x1]!, x2!",
    bytes: &[0x40, 0x14, 0x01, 0x1d],
    expected_status: None,
    fixture: None,
}];

#[test]
fn cpypwt_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
