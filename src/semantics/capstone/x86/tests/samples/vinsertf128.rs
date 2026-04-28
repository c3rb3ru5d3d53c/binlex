use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "vinsertf128",
    instruction: "vinsertf128 ymm0, ymm1, xmm2, 1",
    architecture: Architecture::AMD64,
    bytes: &[0xc4, 0xe3, 0x75, 0x18, 0xc2, 0x01],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn vinsertf128_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
