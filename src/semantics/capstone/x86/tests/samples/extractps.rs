use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "extractps",
    instruction: "extractps eax, xmm0, 1",
    architecture: Architecture::AMD64,
    bytes: &[0x66, 0x0f, 0x3a, 0x17, 0xc0, 0x01],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn extractps_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
