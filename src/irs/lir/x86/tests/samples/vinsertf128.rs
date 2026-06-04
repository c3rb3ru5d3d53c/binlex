use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, irs::lir::LirStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "vinsertf128",
    instruction: "vinsertf128 ymm0, ymm1, xmm2, 1",
    architecture: Architecture::AMD64,
    bytes: &[0xc4, 0xe3, 0x75, 0x18, 0xc2, 0x01],
    expected_status: Some(LirStatus::Complete),
    lir_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn vinsertf128_lir_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
