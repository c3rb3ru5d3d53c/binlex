use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, irs::lir::LirStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "fldlg2",
    instruction: "fldlg2",
    architecture: Architecture::AMD64,
    bytes: &[0xd9, 0xec],
    expected_status: Some(LirStatus::Complete),
    lir_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn fldlg2_lir_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
