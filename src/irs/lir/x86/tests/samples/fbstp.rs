use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, irs::lir::LirStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "fbstp",
    instruction: "fbstp tbyte ptr [rax]",
    architecture: Architecture::AMD64,
    bytes: &[0xdf, 0x30],
    expected_status: Some(LirStatus::Complete),
    lir_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn fbstp_lir_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
