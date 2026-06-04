use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, irs::lir::LirStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "fucomip",
    instruction: "fucomip st(0), st(2)",
    architecture: Architecture::AMD64,
    bytes: &[0xdf, 0xea],
    expected_status: Some(LirStatus::Complete),
    lir_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn fucomip_lir_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
