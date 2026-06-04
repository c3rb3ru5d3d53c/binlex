use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, irs::lir::LirStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "vpinsrw",
    instruction: "vpinsrw xmm0, xmm1, eax, 3",
    architecture: Architecture::AMD64,
    bytes: &[0xc5, 0xf1, 0xc4, 0xc0, 0x03],
    expected_status: Some(LirStatus::Complete),
    lir_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn vpinsrw_lir_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
