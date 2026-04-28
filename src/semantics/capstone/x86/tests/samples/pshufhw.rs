use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "pshufhw",
    instruction: "pshufhw xmm0, xmm1, 0x1b",
    architecture: Architecture::AMD64,
    bytes: &[0xf3, 0x0f, 0x70, 0xc1, 0x1b],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn pshufhw_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
