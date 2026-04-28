use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "fldpi",
    instruction: "fldpi",
    architecture: Architecture::AMD64,
    bytes: &[0xd9, 0xeb],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn fldpi_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
