use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "vpermq",
    instruction: "vpermq ymm0, ymm1, 0x1b",
    architecture: Architecture::AMD64,
    bytes: &[0xc4, 0xe3, 0xfd, 0x00, 0xc1, 0x1b],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn vpermq_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
