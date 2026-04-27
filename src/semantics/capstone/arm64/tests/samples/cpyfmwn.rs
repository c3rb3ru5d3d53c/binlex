use super::{Arm64Sample, assert_sample_statuses};

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "cpyfmwn",
    instruction: "cpyfmwn [x0]!, [x1]!, x2!",
    bytes: &[0x40, 0x44, 0x41, 0x19],
    expected_status: None,
    fixture: None,
}];

#[test]
fn cpyfmwn_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
