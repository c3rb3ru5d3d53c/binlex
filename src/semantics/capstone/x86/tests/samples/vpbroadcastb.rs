use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "vpbroadcastb",
    instruction: "vpbroadcastb xmm0, xmm1",
    architecture: Architecture::AMD64,
    bytes: &[0xc4, 0xe2, 0x79, 0x78, 0xc1],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn vpbroadcastb_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
