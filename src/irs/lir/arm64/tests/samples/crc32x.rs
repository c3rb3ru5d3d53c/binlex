use super::{Arm64Sample, assert_sample_statuses};

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "crc32x",
    instruction: "crc32x w0, w1, x2",
    bytes: &[0x20, 0x4c, 0xc2, 0x9a],
    expected_status: None,
    fixture: None,
}];

#[test]
fn crc32x_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
