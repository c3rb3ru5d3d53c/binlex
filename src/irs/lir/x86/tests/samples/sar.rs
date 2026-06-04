use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, irs::lir::LirStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "sar",
    instruction: "sar eax, 1",
    architecture: Architecture::I386,
    bytes: &[0xd1, 0xf8],
    expected_status: Some(LirStatus::Complete),
    lir_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn sar_lir_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
