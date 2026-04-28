use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "vmovq",
    instruction: "vmovq xmm0, xmm1",
    architecture: Architecture::AMD64,
    bytes: &[0xc5, 0xfa, 0x7e, 0xc1],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn vmovq_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
