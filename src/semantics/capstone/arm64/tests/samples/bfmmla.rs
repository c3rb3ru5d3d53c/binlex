use super::{Arm64Sample, assert_sample_statuses};

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "bfmmla",
    instruction: "bfmmla v0.4s, v1.8h, v2.8h",
    bytes: &[0x20, 0xec, 0x42, 0x6e],
    expected_status: None,
    fixture: None,
}];

#[test]
fn bfmmla_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
