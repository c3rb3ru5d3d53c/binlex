use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "andn",
    instruction: "andn eax, ecx, edx",
    architecture: Architecture::AMD64,
    bytes: &[0xc4, 0xe2, 0x70, 0xf2, 0xc2],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn andn_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
