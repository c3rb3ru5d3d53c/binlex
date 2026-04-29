use super::{Arm64Sample, assert_sample_statuses};
pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "bcax",
    instruction: "bcax v0.16b, v1.16b, v2.16b, v3.16b",
    bytes: &[0x20, 0x0c, 0x22, 0xce],
    expected_status: None,
    fixture: None,
}];

#[test]
fn bcax_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
