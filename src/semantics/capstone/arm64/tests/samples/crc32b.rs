use super::{Arm64Sample, assert_sample_statuses};

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "crc32b",
    instruction: "crc32b w0, w1, w2",
    bytes: &[0x20, 0x40, 0xc2, 0x1a],
    expected_status: None,
    fixture: None,
}];

#[test]
fn crc32b_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
