use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "movabs",
    instruction: "movabs rax, 0x1122334455667788",
    architecture: Architecture::AMD64,
    bytes: &[0x48, 0xb8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn movabs_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
