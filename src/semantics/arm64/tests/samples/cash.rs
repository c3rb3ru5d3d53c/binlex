use super::{Arm64Sample, assert_sample_statuses};

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "cash",
    instruction: "cash w0, w1, [x2]",
    bytes: &[0x41, 0x7c, 0xa0, 0x48],
    expected_status: None,
    fixture: None,
}];

#[test]
fn cash_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
