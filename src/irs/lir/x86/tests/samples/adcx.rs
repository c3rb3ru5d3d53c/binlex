use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, irs::lir::LirStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "adcx",
    instruction: "adcx eax, ebx",
    architecture: Architecture::AMD64,
    bytes: &[0x66, 0x0f, 0x38, 0xf6, 0xc3],
    expected_status: Some(LirStatus::Complete),
    lir_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn adcx_lir_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
