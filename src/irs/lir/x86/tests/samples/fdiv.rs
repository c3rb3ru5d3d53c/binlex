use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, irs::lir::LirStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "fdiv",
    instruction: "fdiv dword ptr [eax]",
    architecture: Architecture::I386,
    bytes: &[0xd8, 0x30],
    expected_status: Some(LirStatus::Complete),
    lir_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn fdiv_lir_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
