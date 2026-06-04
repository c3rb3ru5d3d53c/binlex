use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, irs::lir::LirStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "cmpss",
    instruction: "cmpss xmm0, xmm1, 0",
    architecture: Architecture::AMD64,
    bytes: &[0xf3, 0x0f, 0xc2, 0xc1, 0x00],
    expected_status: Some(LirStatus::Complete),
    lir_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn cmpss_lir_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
