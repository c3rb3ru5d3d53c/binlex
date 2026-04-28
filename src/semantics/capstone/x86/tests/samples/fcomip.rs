use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "fcomip",
    instruction: "fcomip st(0), st(2)",
    architecture: Architecture::AMD64,
    bytes: &[0xdf, 0xf2],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn fcomip_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
