use super::{Arm64Sample, assert_sample_statuses};

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "cpyfewtn",
    instruction: "cpyfewtn [x0]!, [x1]!, x2!",
    bytes: &[0x40, 0xd4, 0x81, 0x19],
    expected_status: None,
    fixture: None,
}];

#[test]
fn cpyfewtn_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
