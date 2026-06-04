use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, irs::lir::LirStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "fdivrp",
    instruction: "fdivrp st(1)",
    architecture: Architecture::I386,
    bytes: &[0xde, 0xf1],
    expected_status: Some(LirStatus::Complete),
    lir_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn fdivrp_lir_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
