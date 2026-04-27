use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "fmulp",
    instruction: "fmulp st(1)",
    architecture: Architecture::I386,
    bytes: &[0xde, 0xc9],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn fmulp_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
