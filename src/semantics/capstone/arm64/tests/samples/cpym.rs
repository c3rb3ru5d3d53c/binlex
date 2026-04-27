use super::{Arm64Sample, assert_sample_statuses};

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "cpym",
    instruction: "cpym [x0]!, [x1]!, x2!",
    bytes: &[0x40, 0x04, 0x41, 0x1d],
    expected_status: None,
    fixture: None,
}];

#[test]
fn cpym_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
