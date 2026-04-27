use super::{Arm64Sample, assert_sample_statuses};

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "cpyfptwn",
    instruction: "cpyfptwn [x0]!, [x1]!, x2!",
    bytes: &[0x40, 0x74, 0x01, 0x19],
    expected_status: None,
    fixture: None,
}];

#[test]
fn cpyfptwn_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
