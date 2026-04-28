use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "cdqe",
    instruction: "cdqe",
    architecture: Architecture::AMD64,
    bytes: &[0x48, 0x98],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn cdqe_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
