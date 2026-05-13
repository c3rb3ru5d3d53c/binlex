use super::{Arm64Sample, assert_sample_statuses};

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "casl",
    instruction: "casl w0, w1, [x2]",
    bytes: &[0x41, 0xfc, 0xa0, 0x88],
    expected_status: None,
    fixture: None,
}];

#[test]
fn casl_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
