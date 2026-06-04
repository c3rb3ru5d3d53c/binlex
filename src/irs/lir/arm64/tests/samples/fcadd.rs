use super::{Arm64Sample, assert_sample_statuses};

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "fcadd",
    instruction: "fcadd v0.2d, v1.2d, v2.2d, #90",
    bytes: &[0x20, 0xe4, 0xc2, 0x6e],
    expected_status: None,
    fixture: None,
}];

#[test]
fn fcadd_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
