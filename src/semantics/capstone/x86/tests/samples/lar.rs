use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "lar",
    instruction: "lar eax, ecx",
    architecture: Architecture::I386,
    bytes: &[0x0f, 0x02, 0xc1],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn lar_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
