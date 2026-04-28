use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "lahf",
    instruction: "lahf",
    architecture: Architecture::AMD64,
    bytes: &[0x9f],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn lahf_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
