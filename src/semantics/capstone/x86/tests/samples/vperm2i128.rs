use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "vperm2i128",
    instruction: "vperm2i128 ymm0, ymm2, ymm1, 0x31",
    architecture: Architecture::AMD64,
    bytes: &[0xc4, 0xe3, 0x6d, 0x46, 0xc1, 0x31],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn vperm2i128_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
