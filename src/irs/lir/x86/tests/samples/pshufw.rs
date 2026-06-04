use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, irs::lir::LirStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "pshufw",
    instruction: "pshufw mm0, mm1, 0x1b",
    architecture: Architecture::AMD64,
    bytes: &[0x0f, 0x70, 0xc1, 0x1b],
    expected_status: Some(LirStatus::Complete),
    lir_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn pshufw_lir_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
