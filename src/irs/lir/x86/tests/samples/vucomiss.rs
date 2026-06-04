use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, irs::lir::LirStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "vucomiss",
    instruction: "vucomiss xmm0, xmm1",
    architecture: Architecture::AMD64,
    bytes: &[0xc5, 0xf8, 0x2e, 0xc1],
    expected_status: Some(LirStatus::Complete),
    lir_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn vucomiss_lir_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
