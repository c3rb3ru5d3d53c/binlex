use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "kmovw",
    instruction: "kmovw k1, k2",
    architecture: Architecture::AMD64,
    bytes: &[0xc5, 0xf8, 0x90, 0xca],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn kmovw_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
