use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "shlx",
    instruction: "shlx eax, ebx, ecx",
    architecture: Architecture::AMD64,
    bytes: &[0xc4, 0xe2, 0x71, 0xf7, 0xc3],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn shlx_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
