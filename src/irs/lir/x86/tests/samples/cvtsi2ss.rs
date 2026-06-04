use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, irs::lir::LirStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "cvtsi2ss",
    instruction: "cvtsi2ss xmm0, eax",
    architecture: Architecture::AMD64,
    bytes: &[0xf3, 0x0f, 0x2a, 0xc0],
    expected_status: Some(LirStatus::Complete),
    lir_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn cvtsi2ss_lir_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
