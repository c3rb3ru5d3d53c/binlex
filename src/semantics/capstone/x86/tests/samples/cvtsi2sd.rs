use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "cvtsi2sd",
    instruction: "cvtsi2sd xmm0, eax",
    architecture: Architecture::AMD64,
    bytes: &[0xf2, 0x0f, 0x2a, 0xc0],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn cvtsi2sd_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
