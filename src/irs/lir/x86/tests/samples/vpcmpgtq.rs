use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, irs::lir::LirStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "vpcmpgtq",
    instruction: "vpcmpgtq xmm0, xmm2, xmm1",
    architecture: Architecture::AMD64,
    bytes: &[0xc4, 0xe2, 0x69, 0x37, 0xc1],
    expected_status: Some(LirStatus::Complete),
    lir_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn vpcmpgtq_lir_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
