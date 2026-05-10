use super::{X86Sample, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "vpmovmskb",
    instruction: "vpmovmskb eax, xmm0",
    architecture: Architecture::AMD64,
    bytes: &[0xc5, 0xf9, 0xd7, 0xc0],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: None,
    roundtrip_fixture: None,
}];

#[test]
fn vpmovmskb_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
