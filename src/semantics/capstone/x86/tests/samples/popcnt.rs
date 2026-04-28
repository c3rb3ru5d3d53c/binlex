use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "popcnt",
    instruction: "popcnt eax, ebx",
    architecture: Architecture::AMD64,
    bytes: &[0xf3, 0x0f, 0xb8, 0xc3],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn popcnt_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
