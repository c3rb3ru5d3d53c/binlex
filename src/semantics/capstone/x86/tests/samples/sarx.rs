use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "sarx",
    instruction: "sarx eax, ebx, ecx",
    architecture: Architecture::AMD64,
    bytes: &[0xc4, 0xe2, 0x72, 0xf7, 0xc3],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn sarx_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
