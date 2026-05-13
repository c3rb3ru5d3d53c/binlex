use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, ir::lir::LirStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "aad",
    instruction: "aad",
    architecture: Architecture::I386,
    bytes: &[0xd5, 0x0a],
    expected_status: Some(LirStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn aad_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
