use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "fimul",
    instruction: "fimul word ptr [rax]",
    architecture: Architecture::AMD64,
    bytes: &[0xde, 0x08],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn fimul_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
