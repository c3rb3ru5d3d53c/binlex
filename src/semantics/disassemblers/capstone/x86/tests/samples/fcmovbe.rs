use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "fcmovbe",
    instruction: "fcmovbe st(0), st(1)",
    architecture: Architecture::AMD64,
    bytes: &[0xda, 0xd1],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn fcmovbe_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
