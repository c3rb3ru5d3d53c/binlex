use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "vcmpss",
    instruction: "vcmpss xmm0, xmm1, xmm2, 0",
    architecture: Architecture::AMD64,
    bytes: &[0xc5, 0xf2, 0xc2, 0xc2, 0x00],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn vcmpss_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
