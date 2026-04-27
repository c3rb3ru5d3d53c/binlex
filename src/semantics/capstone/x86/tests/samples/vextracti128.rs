use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "vextracti128",
    instruction: "vextracti128 xmm0, ymm1, 1",
    architecture: Architecture::AMD64,
    bytes: &[0xc4, 0xe3, 0x7d, 0x39, 0xc8, 0x01],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn vextracti128_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
