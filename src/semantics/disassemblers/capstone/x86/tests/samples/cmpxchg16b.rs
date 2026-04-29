use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "cmpxchg16b",
    instruction: "cmpxchg16b [rax]",
    architecture: Architecture::AMD64,
    bytes: &[0x48, 0x0f, 0xc7, 0x08],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn cmpxchg16b_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
