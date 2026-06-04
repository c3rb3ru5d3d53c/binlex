use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, irs::lir::LirStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "psrlw",
    instruction: "psrlw xmm0, 1",
    architecture: Architecture::AMD64,
    bytes: &[0x66, 0x0f, 0x71, 0xd0, 0x01],
    expected_status: Some(LirStatus::Complete),
    lir_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn psrlw_lir_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
