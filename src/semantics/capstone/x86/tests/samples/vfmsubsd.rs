use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "vfmsubsd",
    instruction: "vfmsubsd xmm0, xmm1, xmm2, xmm3",
    architecture: Architecture::AMD64,
    bytes: &[0xc4, 0xe3, 0xf1, 0x6f, 0xc3, 0x20],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn vfmsubsd_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
