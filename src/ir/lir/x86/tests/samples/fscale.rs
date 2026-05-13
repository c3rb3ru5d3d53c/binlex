use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, ir::lir::LirStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "fscale",
    instruction: "fscale",
    architecture: Architecture::I386,
    bytes: &[0xd9, 0xfd],
    expected_status: Some(LirStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn fscale_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
