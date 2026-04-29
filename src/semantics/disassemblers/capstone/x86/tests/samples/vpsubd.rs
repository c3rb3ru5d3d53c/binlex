use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "vpsubd",
    instruction: "vpsubd xmm0, xmm2, xmm1",
    architecture: Architecture::AMD64,
    bytes: &[0xc5, 0xe9, 0xfa, 0xc1],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn vpsubd_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
