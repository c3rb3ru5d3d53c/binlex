use super::{Arm64Sample, assert_sample_statuses};

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "caspl",
    instruction: "caspl x0, x1, x2, x3, [x4]",
    bytes: &[0x82, 0xfc, 0x20, 0x48],
    expected_status: None,
    fixture: None,
}];

#[test]
fn caspl_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
