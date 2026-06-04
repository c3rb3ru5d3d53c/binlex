use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, irs::lir::LirStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "palignr",
    instruction: "palignr xmm0, xmm1, 8",
    architecture: Architecture::AMD64,
    bytes: &[0x66, 0x0f, 0x3a, 0x0f, 0xc1, 0x08],
    expected_status: Some(LirStatus::Complete),
    lir_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn palignr_lir_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
