use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, irs::lir::LirStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "fcmove",
    instruction: "fcmove st(0), st(1)",
    architecture: Architecture::AMD64,
    bytes: &[0xda, 0xc9],
    expected_status: Some(LirStatus::Complete),
    lir_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn fcmove_lir_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
