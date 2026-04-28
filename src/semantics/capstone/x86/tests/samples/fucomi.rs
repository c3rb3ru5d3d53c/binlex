use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "fucomi",
    instruction: "fucomi st(0), st(2)",
    architecture: Architecture::AMD64,
    bytes: &[0xdb, 0xea],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn fucomi_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
