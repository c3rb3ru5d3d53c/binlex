use super::{Arm64Sample, assert_sample_statuses};
pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "axflag",
    instruction: "axflag",
    bytes: &[0x5f, 0x40, 0x00, 0xd5],
    expected_status: None,
    fixture: None,
}];

#[test]
fn axflag_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
