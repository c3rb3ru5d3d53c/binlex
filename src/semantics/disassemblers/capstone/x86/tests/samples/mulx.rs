use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "mulx",
    instruction: "mulx eax, ebx, ecx",
    architecture: Architecture::AMD64,
    bytes: &[0xc4, 0xe2, 0x63, 0xf6, 0xc1],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn mulx_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
