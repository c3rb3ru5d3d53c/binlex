use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, irs::lir::LirStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "fdivr",
    instruction: "fdivr dword ptr [eax]",
    architecture: Architecture::I386,
    bytes: &[0xd8, 0x38],
    expected_status: Some(LirStatus::Complete),
    lir_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn fdivr_lir_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
