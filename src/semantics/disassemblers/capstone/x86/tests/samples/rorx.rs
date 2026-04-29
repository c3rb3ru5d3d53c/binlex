use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "rorx",
    instruction: "rorx eax, ebx, 7",
    architecture: Architecture::AMD64,
    bytes: &[0xc4, 0xe3, 0x7b, 0xf0, 0xc3, 0x07],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn rorx_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
