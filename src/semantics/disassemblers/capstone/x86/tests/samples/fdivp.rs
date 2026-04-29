use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "fdivp",
    instruction: "fdivp",
    architecture: Architecture::AMD64,
    bytes: &[0xde, 0xf1],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn fdivp_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
