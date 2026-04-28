use super::{Arm64Sample, assert_sample_statuses};

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "cpyfewtrn",
    instruction: "cpyfewtrn [x0]!, [x1]!, x2!",
    bytes: &[0x40, 0x94, 0x81, 0x19],
    expected_status: None,
    fixture: None,
}];

#[test]
fn cpyfewtrn_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
