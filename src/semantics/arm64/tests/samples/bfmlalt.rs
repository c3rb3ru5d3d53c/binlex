use super::{Arm64Sample, assert_sample_statuses};

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "bfmlalt",
    instruction: "bfmlalt v0.4s, v1.8h, v2.8h",
    bytes: &[0x20, 0xfc, 0xc2, 0x6e],
    expected_status: None,
    fixture: None,
}];

#[test]
fn bfmlalt_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
