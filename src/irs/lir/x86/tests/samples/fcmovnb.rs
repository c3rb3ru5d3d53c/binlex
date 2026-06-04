use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, irs::lir::LirStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "fcmovnb",
    instruction: "fcmovnb st(0), st(1)",
    architecture: Architecture::AMD64,
    bytes: &[0xdb, 0xc1],
    expected_status: Some(LirStatus::Complete),
    lir_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn fcmovnb_lir_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
