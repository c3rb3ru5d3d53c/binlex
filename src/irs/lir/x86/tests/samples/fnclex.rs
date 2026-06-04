use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, irs::lir::LirStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "fnclex",
    instruction: "fnclex",
    architecture: Architecture::I386,
    bytes: &[0xdb, 0xe2],
    expected_status: Some(LirStatus::Complete),
    lir_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn fnclex_lir_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
