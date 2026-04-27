use super::{Arm64Sample, assert_sample_statuses};

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "fccmpe",
    instruction: "fccmpe d0, d1, #0, ne",
    bytes: &[0x10, 0x14, 0x61, 0x1e],
    expected_status: None,
    fixture: None,
}];

#[test]
fn fccmpe_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
