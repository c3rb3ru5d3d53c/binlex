use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, irs::lir::LirStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "vpmovsxbq",
    instruction: "vpmovsxbq xmm0, word ptr [rax]",
    architecture: Architecture::AMD64,
    bytes: &[0xc4, 0xe2, 0x79, 0x22, 0x00],
    expected_status: Some(LirStatus::Complete),
    lir_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn vpmovsxbq_lir_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
