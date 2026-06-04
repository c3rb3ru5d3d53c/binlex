use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, irs::lir::LirStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "movntps",
    instruction: "movntps xmmword ptr [rax], xmm0",
    architecture: Architecture::AMD64,
    bytes: &[0x0f, 0x2b, 0x00],
    expected_status: Some(LirStatus::Complete),
    lir_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn movntps_lir_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
