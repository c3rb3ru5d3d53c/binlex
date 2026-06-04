use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, irs::lir::LirStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "fldl2e",
    instruction: "fldl2e",
    architecture: Architecture::AMD64,
    bytes: &[0xd9, 0xea],
    expected_status: Some(LirStatus::Complete),
    lir_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn fldl2e_lir_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
