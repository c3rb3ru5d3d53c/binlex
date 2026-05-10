use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "cmpxchg8b",
    instruction: "lock cmpxchg8b qword ptr [eax]",
    architecture: Architecture::I386,
    bytes: &[0xf0, 0x0f, 0xc7, 0x08],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn cmpxchg8b_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
